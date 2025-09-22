use crate::dns::{AddressFamily, DnsResult, HasAlpn, HasEchConfig, HasIpHint, Protocol};
use hickory_proto::rr::{
    rdata::{a::A, aaaa::AAAA, https::HTTPS, svcb::SVCB},
    RData,
};
use log::trace;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct ConnectionTarget {
    pub domain: String,
    pub address: IpAddr,
    pub protocol: Option<Protocol>,
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
    pub targets: Vec<ConnectionTarget>,
    pub additional_domain_info: HashMap<String, Vec<SVCB>>,
}

impl ConnectionTargetList {
    pub fn new(dns_results: Vec<DnsResult>) -> Self {
        let mut connection_target_list = Self::empty();
        for dns_result in dns_results {
            connection_target_list.add_dns_result(dns_result);
        }
        connection_target_list
    }

    pub fn empty() -> Self {
        Self {
            targets: Vec::new(),
            additional_domain_info: HashMap::new(),
        }
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
            self.add_connection_target(&domain, ip, None, u16::MAX, None, false);
        } else {
            // Use the information from SVCB records to add targets for the given IP address.
            let mut new_targets = Vec::new();
            for svcb in relevant_svcb_records {
                match get_supported_protocols(svcb) {
                    Ok(protocols) => {
                        new_targets.extend(
                            create_connection_targets(&domain, ip, svcb, false, &protocols)
                        )
                    }
                    Err(alpn_ids) => {
                        trace!("ALPN param for domain {} does not contain any supported protocols: {:?}", 
                            domain, alpn_ids);
                        // the service is not supported, so we don't add any targets
                    }
                }
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
        let supported_protocols = match get_supported_protocols(&svcb) {
            Ok(supported_protocols) => supported_protocols,
            Err(alpn_ids) => {
                trace!("ALPN param for domain {} does not contain any supported protocols: {:?}", 
                    domain, alpn_ids);
                return; // We can't use the information in this SVCB record
            }
        };

        // Remove the connection targets created from prior A/AAAA records unless the SVCB record 
        // has IP hints that don't contain the address of the target. 
        // Then add new targets for the A/AAAA IPs using the additional information from the SVCB record.
        let ips: HashSet<IpAddr> = self.targets
            .extract_if(.., |target| {
                target.domain == domain &&
                match &target.address {
                    IpAddr::V4(ip) => !svcb.has_ipv4_hint() || svcb.ipv4_hint_contains_address(ip),
                    IpAddr::V6(ip) => !svcb.has_ipv6_hint() || svcb.ipv6_hint_contains_address(ip),
                }
            })
            .map(|target| target.address)
            .collect();
        for ip in ips {
            self.targets.extend(create_connection_targets(&domain, ip, &svcb, false, &supported_protocols));
        }

        // Add targets for IP hints in SVCB records if the corresponding record (A/AAAA)
        // has not been received yet.
        let has_ipv4_targets = self.targets.iter()
            .any(|target| target.domain == domain && target.address.is_ipv4());
        if !has_ipv4_targets {
            if let Some(ipv4_hints) = svcb.get_ipv4_hint_value() {
                let ips = ipv4_hints.iter().map(|hint| hint.0.into()).collect();
                self.add_connection_targets_from_ip_hints(&domain, ips, &svcb, &supported_protocols);
            }
        }
        let has_ipv6_targets = self.targets.iter()
            .any(|target| target.domain == domain && target.address.is_ipv6());
        if !has_ipv6_targets {
            if let Some(ipv6_hints) = svcb.get_ipv6_hint_value() {
                let ips = ipv6_hints.iter().map(|hint| hint.0.into()).collect();
                self.add_connection_targets_from_ip_hints(&domain, ips, &svcb, &supported_protocols);
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
        protocols: &Option<Vec<Protocol>>,
    ) {
        for ip_addr in ip_hints.iter() {
            self.targets.extend(
                create_connection_targets(domain, *ip_addr, svcb, true, &protocols)
            );
        }
    }

    fn add_connection_target(
        &mut self,
        domain: &str,
        address: IpAddr,
        protocol: Option<Protocol>,
        priority: u16,
        ech_config: Option<Vec<u8>>,
        is_from_svcb: bool,
    ) {
        self.targets.push(ConnectionTarget {
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

/// Maps the ALPN IDs in the SVCB record to the corresponding protocols.
/// Returns a Result that is Err if the list of ALPN IDs is not empty, but does not contain any 
/// supported protocols.
/// Otherwise, returns an Ok containing an Option that is None if the SVCB record does not have 
/// an ALPN param, or Some containing a Vec of the supported protocols.
///
/// Examples:
/// - No ALPN param: Ok(None)
/// - ALPN param "h3": Ok(Some(vec![Protocol::Quic]))
/// - ALPN param "h2,h3": Ok(Some(vec![Protocol::Quic, Protocol::Tcp]))
/// - ALPN param "x,y,z" (no supported protocols): Err(vec!["x", "y", "z"])
fn get_supported_protocols(svcb: &SVCB) -> Result<Option<Vec<Protocol>>, Vec<String>> {
    let Some(alpn_ids) = svcb.get_alpn_ids() else {
        return Ok(None);
    };

    let mut protocols = Vec::new();
    if alpn_ids.contains(&"h3".to_string()) {
        protocols.push(Protocol::Quic);
    }
    if alpn_ids.contains(&"h2".to_string()) {
        protocols.push(Protocol::Tcp);
    }

    if protocols.is_empty() {
        return Err(alpn_ids);
    }
    
    Ok(Some(protocols))
}

fn create_connection_targets(
    domain: &str,
    ip: IpAddr,
    svcb: &SVCB,
    is_from_svcb: bool,
    supported_protocols: &Option<Vec<Protocol>>
) -> Vec<ConnectionTarget> {
    let target = ConnectionTarget {
        domain: domain.to_string(),
        address: ip,
        protocol: None,
        priority: svcb.svc_priority(),
        ech_config: svcb.get_ech_config(),
        is_from_svcb,
        used: false,
    };
    if let Some(ref protocols) = supported_protocols {
        return clone_connection_target_per_protocol(&target, protocols);
    } else {
        return vec![target];
    }
}

/// Clones a ConnectionTarget and once for each provided protocol.
/// If protocols is empty, an empty vector is returned.
/// Otherwise, returns one ConnectionTarget for each protocol from the protocols parameter.
/// The size of the returned vector is always the same as the size of the protocols parameter.
fn clone_connection_target_per_protocol(
    connection_target: &ConnectionTarget,
    protocols: &Vec<Protocol>
) -> Vec<ConnectionTarget> {
    let mut targets = Vec::new();
    for protocol in protocols {
        let mut target = connection_target.clone();
        target.protocol = Some(protocol.clone());
        targets.push(target);
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsResult, Protocol};
    use hickory_proto::rr::{
        domain::Name,
        rdata::{
            a::A,
            aaaa::AAAA,
            https::HTTPS,
            svcb::{Alpn, EchConfigList, IpHint, SvcParamKey, SvcParamValue, SVCB},
        },
        RData, Record,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn create_a_record(domain: &str, ip: Ipv4Addr) -> Record {
        let name = Name::from_utf8(domain).unwrap();
        let rdata = RData::A(A(ip));
        Record::from_rdata(name, 300, rdata)
    }

    fn create_aaaa_record(domain: &str, ip: Ipv6Addr) -> Record {
        let name = Name::from_utf8(domain).unwrap();
        let rdata = RData::AAAA(AAAA(ip));
        Record::from_rdata(name, 300, rdata)
    }

    fn create_https_record(domain: &str, priority: u16, target: &str, svc_params: Vec<(SvcParamKey, SvcParamValue)>) -> Record {
        let name = Name::from_utf8(domain).unwrap();
        let target_name = Name::from_utf8(target).unwrap();
        let svcb = SVCB::new(priority, target_name, svc_params);
        let rdata = RData::HTTPS(HTTPS(svcb));
        Record::from_rdata(name, 300, rdata)
    }

    fn create_svc_params(
        alpn: Option<Vec<&str>>, 
        ipv4_hints: Option<Vec<Ipv4Addr>>, 
        ipv6_hints: Option<Vec<Ipv6Addr>>,
        ech_config: Option<Vec<u8>>
    ) -> Vec<(SvcParamKey, SvcParamValue)> {
        let mut svc_params = Vec::new();

        if let Some(alpn) = alpn {
            svc_params.push(create_alpn_param(alpn));
        }

        if let Some(ipv4_hints) = ipv4_hints {
            let a_records: Vec<A> = ipv4_hints.into_iter().map(A::from).collect();
            svc_params.push((SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(IpHint(a_records))));
        }

        if let Some(ipv6_hints) = ipv6_hints {
            let aaaa_records: Vec<AAAA> = ipv6_hints.into_iter().map(AAAA::from).collect();
            svc_params.push((SvcParamKey::Ipv6Hint, SvcParamValue::Ipv6Hint(IpHint(aaaa_records))));
        }

        if let Some(ech_config) = ech_config {
            svc_params.push((SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(EchConfigList(ech_config))));
        }

        svc_params
    }

    fn create_alpn_param(protocols: Vec<&str>) -> (SvcParamKey, SvcParamValue) {
        let protocols = protocols.into_iter().map(|s| s.to_string()).collect();
        (SvcParamKey::Alpn, SvcParamValue::Alpn(Alpn(protocols)))
    }

    #[test]
    fn test_add_aaaa_after_two_https_records() {
        let mut target_list = ConnectionTargetList::empty();

        let domain = "example.com.";
        let test_ip = Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334);

        // Create and add HTTPS records - first with target "." (root), second with alternative target
        let svc_params = create_svc_params(Some(vec!["h3"]), None, None, None);
        let https_record1 = create_https_record(domain, 1, ".", svc_params.clone());
        let https_record2 = create_https_record(domain, 2, "alt.example.com.", svc_params);
        target_list.add_dns_result(DnsResult::PositiveDnsResult(vec![https_record1, https_record2]));

        // Verify we have the SVCB info stored, but no ConnectionTargets
        assert_eq!(target_list.additional_domain_info.len(), 2);
        assert!(target_list.additional_domain_info.contains_key(domain));
        assert!(target_list.additional_domain_info.contains_key("alt.example.com."));
        assert!(target_list.targets.is_empty());

        // Now add AAAA record
        let aaaa_record = create_aaaa_record(domain, test_ip);
        target_list.add_dns_result(DnsResult::PositiveDnsResult(vec![aaaa_record]));
        assert_eq!(target_list.targets.len(), 1);

        // Verify that the target was created with SVCB data from the first HTTPS record
        let target = target_list.targets.first().unwrap();
        assert_eq!(target.domain, domain);
        assert_eq!(target.address, IpAddr::V6(test_ip));
        assert_eq!(target.protocol, Some(Protocol::Quic));
        assert_eq!(target.priority, 1);
        assert_eq!(target.ech_config, None);
        assert_eq!(target.is_from_svcb, false);
        assert_eq!(target.used, false);
    }

    #[test]
    fn test_add_aaaa_before_two_https_records() {
        let mut target_list = ConnectionTargetList::empty();

        let domain = "example.com.";
        let test_ip = Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334);

        // Add AAAA record first
        let aaaa_record = create_aaaa_record(domain, test_ip);
        target_list.add_dns_result(DnsResult::PositiveDnsResult(vec![aaaa_record]));

        // Verify we have a basic target without SVCB data
        assert_eq!(target_list.targets.len(), 1);
        assert_eq!(target_list.targets[0].priority, u16::MAX);
        assert!(target_list.targets[0].protocol.is_none());

        // Create and add HTTPS records - first with target "." (root), second with alternative target
        let svc_params = create_svc_params(Some(vec!["h2", "h3"]), None, None, None);
        let https_record1 = create_https_record(domain, 1, ".", svc_params.clone());
        let https_record2 = create_https_record(domain, 2, "alt.example.com.", svc_params);
        target_list.add_dns_result(DnsResult::PositiveDnsResult(vec![https_record1, https_record2]));

        // Verify that the original target was replaced with HTTPS-enhanced targets
        assert_eq!(target_list.targets.len(), 2);
        
        assert_eq!(target_list.targets[0].domain, domain);
        assert_eq!(target_list.targets[0].address, IpAddr::V6(test_ip));
        assert_eq!(target_list.targets[0].protocol, Some(Protocol::Quic));
        assert_eq!(target_list.targets[0].priority, 1);
        assert_eq!(target_list.targets[0].ech_config, None);
        assert_eq!(target_list.targets[0].is_from_svcb, false);
        assert_eq!(target_list.targets[0].used, false);
        
        assert_eq!(target_list.targets[1].domain, domain);
        assert_eq!(target_list.targets[1].address, IpAddr::V6(test_ip));
        assert_eq!(target_list.targets[1].protocol, Some(Protocol::Tcp));
        assert_eq!(target_list.targets[1].priority, 1);
        assert_eq!(target_list.targets[1].ech_config, None);
        assert_eq!(target_list.targets[1].is_from_svcb, false);
        assert_eq!(target_list.targets[1].used, false);
    }

    #[test]
    fn test_get_supported_protocols_no_alpn_param() {
        let svcb_no_alpn = SVCB::new(1, Name::from_utf8("example.com.").unwrap(), vec![]);
        let result = get_supported_protocols(&svcb_no_alpn);
        assert!(matches!(result, Ok(None)), "Expected Ok(None) for no ALPN param");
    }

    #[test]
    fn test_get_supported_protocols_alpn_param_with_supported_protocols() {
        let alpn = vec![create_alpn_param(vec!["h3"])];
        let svcb = SVCB::new(1, Name::from_utf8("example.com.").unwrap(), alpn);
        let result = get_supported_protocols(&svcb);

        assert!(matches!(result, Ok(Some(_))));
        let protocols = result.unwrap().unwrap();
        assert_eq!(protocols.len(), 1);
        assert_eq!(protocols[0], Protocol::Quic);
    }

    #[test]
    fn test_get_supported_protocols_alpn_param_with_only_unsupported_protocols() {
        let alpn = vec![create_alpn_param(vec!["HTTP/0.9", "FTP"])];
        let svcb = SVCB::new(1, Name::from_utf8("example.com.").unwrap(), alpn);
        let result = get_supported_protocols(&svcb);
        
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), vec!["HTTP/0.9".to_string(), "FTP".to_string()]);
    }

    #[test]
    fn test_clone_connection_target_per_protocol() {
        let base_target = ConnectionTarget {
            domain: "example.com".to_string(),
            address: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334)),
            protocol: None,
            priority: 1,
            ech_config: None,
            is_from_svcb: false,
            used: false,
        };

        // Test case 1: Empty protocols vec should return empty vec
        let empty_protocols = vec![];
        let result = clone_connection_target_per_protocol(&base_target, &empty_protocols);
        assert_eq!(result.len(), 0, "Empty protocols should result in empty target list");

        // Test case 2: Single protocol should return single target
        let single_protocol = vec![Protocol::Quic];
        let result = clone_connection_target_per_protocol(&base_target, &single_protocol);
        assert_eq!(result.len(), 1, "Single protocol should result in single target");
        assert_eq!(result[0].protocol, Some(Protocol::Quic));

        // Test case 3: Multiple protocols should return equal number of targets
        let multiple_protocols = vec![Protocol::Quic, Protocol::Tcp];
        let result = clone_connection_target_per_protocol(&base_target, &multiple_protocols);
        assert_eq!(result.len(), 2, "Two protocols should result in two targets");
        
        // Verify each protocol is represented
        let quic_targets = result.iter().filter(|t| t.protocol == Some(Protocol::Quic)).count();
        let tcp_targets = result.iter().filter(|t| t.protocol == Some(Protocol::Tcp)).count();
        assert_eq!(quic_targets, 1, "Should have exactly one QUIC target");
        assert_eq!(tcp_targets, 1, "Should have exactly one TCP target");

        // Verify other fields are preserved
        for target in &result {
            assert_eq!(target.domain, base_target.domain);
            assert_eq!(target.address, base_target.address);
            assert_eq!(target.priority, base_target.priority);
            assert_eq!(target.ech_config, base_target.ech_config);
            assert_eq!(target.is_from_svcb, base_target.is_from_svcb);
            assert_eq!(target.used, base_target.used);
        }
    }

    #[test]
    fn test_connection_target_list_basic_operations() {
        let mut target_list = ConnectionTargetList::empty();
        
        // Test initial state
        assert_eq!(target_list.len(), 0);
        assert!(!target_list.has_remaining());
        assert!(target_list.get_next_target().is_none());

        // Add a target manually for testing
        target_list.add_connection_target(
            "example.com",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            Some(Protocol::Tcp),
            1,
            None,
            false,
        );

        assert_eq!(target_list.len(), 1);
        assert!(target_list.has_remaining());

        // Get the target
        let target = target_list.get_next_target().unwrap();
        assert_eq!(target.domain, "example.com");
        assert_eq!(target.address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(target.protocol, Some(Protocol::Tcp));
        assert_eq!(target.priority, 1);
        assert!(target.used);

        // No more targets should be available
        assert!(!target_list.has_remaining());
        assert!(target_list.get_next_target().is_none());
    }

    #[test]
    fn test_add_a_record_after_https_record_with_ipv4_hint() {
        let mut target_list = ConnectionTargetList::empty();

        let domain = "example.com.";
        let ip = Ipv4Addr::new(192, 168, 1, 10);

        // First add HTTPS record with IP hint
        let svc_params = create_svc_params(Some(vec!["h3"]), Some(vec![ip]), None, None);
        let https_record = create_https_record(domain, 1, ".", svc_params);
        target_list.add_dns_result(DnsResult::PositiveDnsResult(vec![https_record]));

        // Verify we have a target from the IP hint
        assert_eq!(target_list.targets.len(), 1);
        assert_eq!(target_list.targets[0].domain, domain);
        assert_eq!(target_list.targets[0].address, IpAddr::V4(ip));
        assert_eq!(target_list.targets[0].protocol, Some(Protocol::Quic));
        assert_eq!(target_list.targets[0].priority, 1);
        assert_eq!(target_list.targets[0].is_from_svcb, true);

        // Now add A record for the same domain and same IP
        let a_record = create_a_record(domain, ip);
        target_list.add_dns_result(DnsResult::PositiveDnsResult(vec![a_record]));

        // The target from IP hint should be replaced with one from A record
        assert_eq!(target_list.targets.len(), 1);
        assert_eq!(target_list.targets[0].domain, domain);
        assert_eq!(target_list.targets[0].address, IpAddr::V4(ip));
        assert_eq!(target_list.targets[0].protocol, Some(Protocol::Quic));
        assert_eq!(target_list.targets[0].priority, 1);
        assert_eq!(target_list.targets[0].is_from_svcb, false); // This should be false since it's from the A record
    }

    // Same test as above, but with the IP hint being different from the A record IP
    #[test]
    fn test_add_a_record_after_https_record_with_different_ipv4_hint() {
        let mut target_list = ConnectionTargetList::empty();

        let domain = "example.com.";
        let a_record_ip = Ipv4Addr::new(192, 168, 1, 10);
        let hint_ip = Ipv4Addr::new(192, 168, 1, 20);

        // First add HTTPS record with IP hint
        let svc_params = create_svc_params(Some(vec!["h3"]), Some(vec![hint_ip]), None, None);
        let https_record = create_https_record(domain, 1, ".", svc_params);
        target_list.add_dns_result(DnsResult::PositiveDnsResult(vec![https_record]));

        // Verify we have a target from the IP hint
        assert_eq!(target_list.targets.len(), 1);
        assert_eq!(target_list.targets[0].domain, domain);
        assert_eq!(target_list.targets[0].address, IpAddr::V4(hint_ip));
        assert_eq!(target_list.targets[0].protocol, Some(Protocol::Quic));
        assert_eq!(target_list.targets[0].priority, 1);
        assert_eq!(target_list.targets[0].is_from_svcb, true);

        // Now add A record for the same domain but different IP
        let a_record = create_a_record(domain, a_record_ip);
        target_list.add_dns_result(DnsResult::PositiveDnsResult(vec![a_record]));

        // The target from IP hint should be replaced with one from A record, and the SVCB info should not be applied
        assert_eq!(target_list.targets.len(), 1);
        assert_eq!(target_list.targets[0].domain, domain);
        assert_eq!(target_list.targets[0].address, IpAddr::V4(a_record_ip));
        assert_eq!(target_list.targets[0].protocol, None);
        assert_eq!(target_list.targets[0].priority, u16::MAX);
        assert_eq!(target_list.targets[0].is_from_svcb, false);
    }

    #[test]
    fn test_add_a_record_before_https_record_with_different_ipv4_hint() {
        let mut target_list = ConnectionTargetList::empty();

        let domain = "example.com.";
        let a_record_ip = Ipv4Addr::new(192, 168, 1, 20);
        let hint_ip = Ipv4Addr::new(192, 168, 1, 30); // Different IP than in A record

        // First add A record
        let a_record = create_a_record(domain, a_record_ip);
        target_list.add_dns_result(DnsResult::PositiveDnsResult(vec![a_record]));

        // Verify we have a basic target without HTTPS data
        assert_eq!(target_list.targets.len(), 1);
        assert_eq!(target_list.targets[0].domain, domain);
        assert_eq!(target_list.targets[0].address, IpAddr::V4(a_record_ip));
        assert_eq!(target_list.targets[0].priority, u16::MAX);
        assert!(target_list.targets[0].protocol.is_none());
        assert_eq!(target_list.targets[0].is_from_svcb, false);

        // Now add HTTPS record with different IP hint
        let svc_params = create_svc_params(Some(vec!["h3"]), Some(vec![hint_ip]), None, None);
        let https_record = create_https_record(domain, 1, ".", svc_params);
        target_list.add_dns_result(DnsResult::PositiveDnsResult(vec![https_record]));

        // Should now have only one target
        // The target should be from the A record without the SVCB info, as the iphint doesn't match
        assert_eq!(target_list.targets.len(), 1);
        let target = &target_list.targets[0];
        assert_eq!(target.domain, domain);
        assert_eq!(target.address, IpAddr::V4(a_record_ip));
        assert_eq!(target.protocol, None);
        assert_eq!(target.priority, u16::MAX);
        assert_eq!(target.is_from_svcb, false);
    }

    #[test]
    fn test_add_https_record_with_alpn_and_ipv4_and_ipv6_hints() {
        let mut target_list = ConnectionTargetList::empty();

        let domain = "example.com.";
        let ipv4_hint = Ipv4Addr::new(192, 168, 1, 10);
        let ipv6_hint = Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334);

        // Add HTTPS record with both IPv4 and IPv6 hints
        let svc_params = create_svc_params(
            Some(vec!["h2", "h3"]),
            Some(vec![ipv4_hint]),
            Some(vec![ipv6_hint]),
            None
        );
        let https_record = create_https_record(domain, 1, ".", svc_params);
        target_list.add_dns_result(DnsResult::PositiveDnsResult(vec![https_record]));

        // Should have 2 targets for IPv4 and IPv6 hints each
        assert_eq!(target_list.targets.len(), 4);

        let result = target_list.targets.iter()
            .map(|target| (target.address, target.protocol))
            .collect::<Vec<_>>();
        assert!(result.contains(&(IpAddr::V4(ipv4_hint), Some(Protocol::Tcp))));
        assert!(result.contains(&(IpAddr::V4(ipv4_hint), Some(Protocol::Quic))));
        assert!(result.contains(&(IpAddr::V6(ipv6_hint), Some(Protocol::Tcp))));
        assert!(result.contains(&(IpAddr::V6(ipv6_hint), Some(Protocol::Quic))));

    }
}
