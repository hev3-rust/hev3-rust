use crate::dns::{AddressFamily, DnsResult, HasAlpn, HasEchConfig, HasIpHint, Protocol};
use hickory_proto::rr::{
    rdata::{a::A, aaaa::AAAA, https::HTTPS, svcb::SVCB},
    RData,
};
use std::collections::HashMap;
use std::{collections::VecDeque, net::IpAddr};

#[derive(Debug)]
pub struct ConnectionTarget {
    pub domain: String,
    pub address: IpAddr,
    pub protocol: Protocol,
    pub priority: u16,
    pub ech_config: Option<Vec<u8>>,
    pub is_from_svcb: bool,
}

impl ConnectionTarget {
    pub fn has_ech_config(&self) -> bool {
        self.ech_config.is_some()
    }
}

pub struct ConnectionTargetList {
    pub targets: VecDeque<ConnectionTarget>,
    pub additional_domain_info: HashMap<String, Vec<SVCB>>,
}

impl ConnectionTargetList {
    pub fn new(dns_results: Vec<DnsResult>) -> Self {
        let mut connection_target_list = Self {
            targets: VecDeque::new(),
            additional_domain_info: HashMap::new(),
        };
        for dns_result in dns_results {
            connection_target_list.add_dns_result(dns_result);
        }
        connection_target_list
    }

    pub fn len(&self) -> usize {
        self.targets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    pub fn pop_next_target(&mut self) -> Option<ConnectionTarget> {
        self.targets.pop_front()
    }

    pub fn add_dns_result(&mut self, dns_result: DnsResult) {
        match dns_result.record {
            RData::A(A(ip)) => {
                self.remove_targets_from_svcb(&dns_result.domain, AddressFamily::IPv4);
                self.add_a_or_aaaa(&dns_result.domain, ip.into());
            }
            RData::AAAA(AAAA(ip)) => {
                self.remove_targets_from_svcb(&dns_result.domain, AddressFamily::IPv6);
                self.add_a_or_aaaa(&dns_result.domain, ip.into());
            }
            RData::HTTPS(HTTPS(svcb)) | RData::SVCB(svcb) => {
                self.add_svcb(&dns_result.domain, svcb);
            }
            _ => {
                // TODO: handle other record types? CNAME?
            }
        }
    }

    /// Removes all targets of a given address family that originate from IP hints in SVCB records
    fn remove_targets_from_svcb(
        &mut self, 
        domain: &str, 
        address_family: AddressFamily
    ) {
        self.targets.retain(|target| {
            !(target.domain == domain
                && address_family.matches(&target.address)
                && target.is_from_svcb)
        });
    }

    fn add_a_or_aaaa(
        &mut self, 
        domain: &str, 
        ip: IpAddr
    ) {
        let relevant_svcb_records = self.get_relevant_svcb_records_for_target(domain, &ip);

        if relevant_svcb_records.is_empty() {
            // We have no information about protocol preferences, 
            // so we add a target for both QUIC and TCP
            self.add_connection_target(domain, ip, Protocol::Tcp, u16::MAX, None, false);
            self.add_connection_target(domain, ip, Protocol::Quic, u16::MAX, None, false);
        } else {
            // Use the information from SVCB records to add targets for the given IP address.
            // Due to Rust's borrowing rules, we need to collect all relevant svcb data first.
            // relevant_svcb_records holds a reference to self, so we cannot access 
            // self.add_connection_target inside the loop, as it needs a mutable reference to self.
            let mut svcb_data = Vec::new();
            for svcb_record in relevant_svcb_records {
                for protocol in self.get_supported_protocols(svcb_record) {
                    svcb_data.push((
                        svcb_record.svc_priority(),
                        protocol,
                        svcb_record.get_ech_config(),
                    ));
                }
            }
            for (priority, protocol, ech_config) in svcb_data {
                self.add_connection_target(domain, ip, protocol, priority, ech_config, false);
            }
        }
    }

    /// Returns all SVCB records in additional_domain_info that match the domain and
    /// either have no IP hints or contain an IP hint for the given IP address.
    fn get_relevant_svcb_records_for_target(
        &self, 
        domain: &str, 
        ip: &IpAddr
    ) -> Vec<&SVCB> {
        let Some(svcb_records) = self.additional_domain_info.get(domain) else {
            return vec![];
        };
        return svcb_records
            .iter()
            .filter(|svcb| match ip {
                IpAddr::V4(ip) => !svcb.has_ipv4_hint() || svcb.ipv4_hint_contains_address(ip),
                IpAddr::V6(ip) => !svcb.has_ipv6_hint() || svcb.ipv6_hint_contains_address(ip),
            })
            .collect();
    }

    fn add_svcb(
        &mut self, 
        domain: &str, 
        svcb: SVCB
    ) {
        // Remove Connection Targets from prior A/AAAA records if the protocol is not supported
        let supported_protocols = self.get_supported_protocols(&svcb);
        self.targets.retain(|target| {
            target.domain != domain || supported_protocols.contains(&target.protocol)
        });

        // Update the connection targets created from prior A/AAAA records with the priority and 
        // ECH config from the SVCB record.
        let mut has_ipv4_targets = false;
        let mut has_ipv6_targets = false;
        for target in self.targets.iter_mut() {
            if target.domain != domain {
                continue;
            }
            target.priority = svcb.svc_priority();
            target.ech_config = svcb.get_ech_config();
            
            match target.address {
                IpAddr::V4(_) => has_ipv4_targets = true,
                IpAddr::V6(_) => has_ipv6_targets = true,
            }
        }
        
        // Add targets for IP hints in SVCB records if the corresponding record (A/AAAA)
        // has not been received yet.
        if svcb.has_ipv4_hint() && !has_ipv4_targets {
            for protocol in self.get_supported_protocols(&svcb) {
                for ip_hint in svcb.get_ipv4_hint_value().unwrap() {
                    self.add_connection_target(
                        domain,
                        ip_hint.0.into(),
                        protocol.clone(),
                        u16::MAX,
                        None,
                        true,
                    );
                }
            }
        } else if svcb.has_ipv6_hint() && !has_ipv6_targets {
            for protocol in self.get_supported_protocols(&svcb) {
                for ip_hint in svcb.get_ipv6_hint_value().unwrap() {
                    self.add_connection_target(
                        domain,
                        ip_hint.0.into(),
                        protocol.clone(),
                        u16::MAX,
                        None,
                        true,
                    );
                }
            }
        }

        // Store the record, as it contains information for A/AAAA records that might arrive later
        self.additional_domain_info
            .entry(domain.to_string())
            .or_insert_with(Vec::new)
            .push(svcb);
    }

    fn get_supported_protocols(&self, svcb: &SVCB) -> Vec<Protocol> {
        let mut protocols = Vec::new();
        if !svcb.has_alpn_param() || svcb.has_alpn_id("h3") {
            protocols.push(Protocol::Quic);
        }
        if !svcb.has_alpn_param() || svcb.has_alpn_id("h2") {
            protocols.push(Protocol::Tcp);
        }
        protocols
    }

    fn add_connection_target(
        &mut self,
        domain: &str,
        address: IpAddr,
        protocol: Protocol,
        priority: u16,
        ech_config: Option<Vec<u8>>,
        is_from_svcb: bool,
    ) {
        self.targets.push_back(ConnectionTarget{
            domain: domain.to_string(),
            address,
            protocol,
            priority,
            ech_config,
            is_from_svcb,
        });
    }
}
