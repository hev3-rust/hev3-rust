use crate::dns::{AddressFamily, DnsResult, HasAlpn, HasEchConfig, HasIpHint, Protocol};
use hickory_proto::rr::{
    rdata::{a::A, aaaa::AAAA, https::HTTPS, svcb::SVCB},
    RData,
};
use log::trace;
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
    pub used: bool,
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

    pub fn has_remaining(&self) -> bool {
        self.targets.iter().any(|target| !target.used)
    }

    pub fn get_next_target(&mut self) -> Option<&ConnectionTarget> {
        let next = self.targets.iter_mut().find(|target| !target.used)?;
        next.used = true;
        Some(next)
    }

    pub fn add_dns_result(&mut self, dns_result: DnsResult) {
        let DnsResult::PositiveDnsResult(records) = dns_result else {
            // We can ignore negative DNS results here
            return;
        };
        for record in records {
            match record.data() {
                RData::A(A(ip)) => {
                    self.remove_targets_from_svcb(record.name().to_utf8(), AddressFamily::IPv4);
                    self.add_a_or_aaaa(record.name().to_utf8(), (*ip).into());
                }
                RData::AAAA(AAAA(ip)) => {
                    self.remove_targets_from_svcb(record.name().to_utf8(), AddressFamily::IPv6);
                    self.add_a_or_aaaa(record.name().to_utf8(), (*ip).into());
                }
                RData::HTTPS(HTTPS(svcb)) | RData::SVCB(svcb) => {
                    let domain = if svcb.target_name().is_root() {
                        record.name().to_utf8()
                    } else {
                        svcb.target_name().to_utf8()
                    };
                    self.add_svcb(domain, svcb.clone());
                }
                _ => {}
            }
        }
    }

    /// Removes all targets of a given address family that originate from IP hints in SVCB records
    fn remove_targets_from_svcb(
        &mut self, 
        domain: String, 
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
        domain: String, 
        ip: IpAddr
    ) {
        let relevant_svcb_records = self.get_relevant_svcb_records_for_target(&domain, &ip);

        if relevant_svcb_records.is_empty() {
            // We have no information about protocol preferences,
            // so we add a target for both QUIC and TCP
            self.add_connection_target(&domain, ip, Protocol::Tcp, u16::MAX, None, false);
            self.add_connection_target(&domain, ip, Protocol::Quic, u16::MAX, None, false);
        } else {
            // Use the information from SVCB records to add targets for the given IP address.
            let mut new_targets = Vec::new();
            for svcb_record in relevant_svcb_records {
                for protocol in self.get_supported_protocols(svcb_record) {
                    new_targets.push(ConnectionTarget {
                        domain: domain.clone(),
                        address: ip,
                        protocol,
                        priority: svcb_record.svc_priority(),
                        ech_config: svcb_record.get_ech_config(),
                        is_from_svcb: false,
                        used: false,
                    });
                }
                trace!("Add {} targets for domain {} and IP {}", new_targets.len(), domain, ip);
            }
            self.targets.extend(new_targets);
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
        domain: String, 
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
        if !has_ipv4_targets {
            if let Some(ipv4_hints) = svcb.get_ipv4_hint_value() {
                let ips = ipv4_hints.iter().map(|hint| hint.0.into()).collect();
                self.add_connection_targets_from_ip_hints(&domain, ips, &svcb);
            }
        } else if !has_ipv6_targets {
            if let Some(ipv6_hints) = svcb.get_ipv6_hint_value() {
                let ips = ipv6_hints.iter().map(|hint| hint.0.into()).collect();
                self.add_connection_targets_from_ip_hints(&domain, ips, &svcb);
            }
        }

        // Store the record, as it contains information for A/AAAA records that might arrive later
        self.additional_domain_info
            .entry(domain)
            .or_insert_with(Vec::new)
            .push(svcb);
    }

    fn add_connection_targets_from_ip_hints(
        &mut self,
        domain: &str,
        ip_hints: Vec<IpAddr>,
        svcb: &SVCB,
    ) {
        let ech_config = svcb.get_ech_config();
        for protocol in self.get_supported_protocols(&svcb) {
            for ip_addr in ip_hints.iter() {
                self.add_connection_target(
                    &domain,
                    *ip_addr,
                    protocol.clone(),
                    svcb.svc_priority(),
                    ech_config.clone(),
                    true,
                );
            }
        }
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
        self.targets.push_back(ConnectionTarget {
            domain: domain.to_string(),
            address,
            protocol,
            priority,
            ech_config,
            is_from_svcb,
            used: false,
        });
    }
}
