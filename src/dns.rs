use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr}, sync::Arc, time::Duration};
use hickory_resolver::{TokioResolver, lookup::Lookup};
use hickory_proto::rr::{rdata::{https::HTTPS, svcb::{SvcParamKey, SVCB}, A, AAAA}, RData, RecordType};
use tokio::sync::mpsc::{Receiver, Sender};
use rand::seq::IndexedRandom;
use crate::hev3_client::{Result, Hev3Error};
use log::debug;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Quic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressFamily {
    IPv4,
    IPv6,
}

impl AddressFamily {
    pub fn from_ip(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V6(_) => AddressFamily::IPv6,
            IpAddr::V4(_) => AddressFamily::IPv4,
        }
    }

    /// Does this address family match the family of the IpAddr?
    pub fn matches(&self, ip: &IpAddr) -> bool {
        self == &AddressFamily::from_ip(ip)
    }
}

#[derive(Debug, Clone)]
pub struct DnsResult {
    pub domain: String,
    pub record: RData,
}

impl DnsResult {
    pub fn new(domain: String, record: RData) -> Self {
        Self { domain, record }
    }
}

////////////////////////////////////////////////////////////////////////////////
// DNS resolution logic
////////////////////////////////////////////////////////////////////////////////

pub fn init_queries(
    resolver: &TokioResolver, 
    hostname: &str
) -> Receiver<DnsResult> {
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    
    let resolver = Arc::new(resolver.clone()); // TODO: Mutex?

    // TODO: respect config.use_svcb_instead_of_https
    start_dns_lookup_concurrently(resolver.clone(), hostname, RecordType::HTTPS, &tx);
    start_dns_lookup_concurrently(resolver.clone(), hostname, RecordType::AAAA, &tx);
    start_dns_lookup_concurrently(resolver.clone(), hostname, RecordType::A, &tx);

    rx
}

fn start_dns_lookup_concurrently(
    resolver: Arc<TokioResolver>, 
    hostname: &str, 
    record_type: RecordType, 
    tx: &Sender<DnsResult>
) {
    let hostname = hostname.to_string();
    let tx = tx.clone();

    tokio::spawn(async move {
        let result = resolver.lookup(&hostname, record_type).await;

        match result {
            Ok(lookup) => handle_successful_lookup(&lookup, &hostname, resolver, &tx).await,
            Err(e) => {
                // TODO: handle errors more appropriately
                // "no records found" is acceptable, maybe no logging needed?
                // others might be a problem - panic?
                println!("DNS resolution error: {:?}", e.to_string());
            }
        }
    });
}

async fn handle_successful_lookup(
    lookup: &Lookup, 
    hostname: &str,
    resolver: Arc<TokioResolver>, 
    tx: &Sender<DnsResult>
) {
    if lookup.records().is_empty() {
        debug!("Empty {} RRset for {}", lookup.query().query_type(), lookup.query().name());
        return;
    }

    let mut svcb_records = Vec::new();
    for record in lookup.iter() {
        match record {
            RData::A(_) | RData::AAAA(_) => {
                tx.send(DnsResult::new(hostname.to_string(), record.clone())).await.unwrap();
            }
            RData::HTTPS(HTTPS(record)) | RData::SVCB(record) => {
                // SVCB/HTTPS records are handled in bulk
                svcb_records.push(record);
            }
            _ => {
                println!("Unknown record: {:?}", record);
            }
        }
    }
    handle_svcb_records(svcb_records, resolver, hostname, &tx).await;
}

async fn handle_svcb_records(
    svcb_records: Vec<&SVCB>, 
    resolver: Arc<TokioResolver>,
    hostname: &str,
    tx: &Sender<DnsResult>
) {
    // Check if any records are in alias mode (priority 0)
    let alias_records: Vec<&SVCB> = filter_svcb_records_in_alias_mode(&svcb_records);

    // If we have alias records, ignore any service mode records [RFC 9460]
    if !alias_records.is_empty() {
        handle_svcb_alias_mode_records(&alias_records, resolver, tx);
    } else {
        for record in svcb_records {
            let rdata = RData::HTTPS(HTTPS(record.clone()));
            tx.send(DnsResult::new(hostname.to_string(), rdata)).await.unwrap();
        }
    }
}

fn filter_svcb_records_in_alias_mode<'a>(
    svcb_records: &Vec<&'a SVCB>
) -> Vec<&'a SVCB> {
    svcb_records.iter().copied().filter(|r| r.svc_priority() == 0).collect()
}

/// Chooses one target name randomly from the alias records and resolves it [RFC 9460]
fn handle_svcb_alias_mode_records(
    alias_records: &Vec<&SVCB>, 
    resolver: Arc<TokioResolver>, 
    tx: &Sender<DnsResult>
) {
    if let Some(record) = alias_records.choose(&mut rand::rng()) {
        // TODO loop detection.
        start_dns_lookup_concurrently(
            resolver.clone(),
            &record.target_name().to_utf8(),
            RecordType::HTTPS, // TODO config.use_svcb_instead_of_https
            tx
        );
    }
}

////////////////////////////////////////////////////////////////////////////////
// Resolution delay: Waiting for addresses
////////////////////////////////////////////////////////////////////////////////

/// TODO: implement new logic
/// Wait for the resolution delay period to collect DNS responses 
/// or until an HTTPS record with IPv6 address is found
/// Returns all results received during the delay period
pub async fn wait_for_dns_results(
    rx: &mut Receiver<DnsResult>, 
    resolution_delay: Duration
) -> Result<Vec<DnsResult>> {
    let mut dns_results = Vec::new();

    dns_results.push(wait_for_first_dns_result(rx).await?);

    tokio::select! {
        // Wait for more results
        _ = async {
            while let Some(dns_result) = rx.recv().await {
                dns_results.push(dns_result);
            }
        } => {}
        // Resolution delay timeout
        _ = tokio::time::sleep(resolution_delay) => {}
    }
    
    Ok(dns_results)
}

async fn wait_for_first_dns_result(rx: &mut Receiver<DnsResult>) -> Result<DnsResult> {
    match rx.recv().await {
        Some(first_dns_result) => {
            println!("First DNS result received: {:?}", first_dns_result);
            Ok(first_dns_result)
        }
        None => {
            println!("No addresses found");
            Err(Hev3Error::NoAddressesFound)
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Helper methods for SVCB records
////////////////////////////////////////////////////////////////////////////////

pub trait HasIpHint {
    fn has_ipv4_hint(&self) -> bool;
    fn has_ipv6_hint(&self) -> bool;

    /// Determines whether an address is contained in the ipv4_hint param.
    /// Returns false if the record does not have an ipv4_hint param.
    fn ipv4_hint_contains_address(&self, ip: &Ipv4Addr) -> bool;

    /// Determines whether an address is contained in the ipv6_hint param.
    /// Returns false if the record does not have an ipv6_hint param.
    fn ipv6_hint_contains_address(&self, ip: &Ipv6Addr) -> bool;

    /// Returns the value of the record's ipv4_hint param.
    /// Returns None if the record does not have an ipv4_hint param.
    fn get_ipv4_hint_value(&self) -> Option<Vec<A>>;

    /// Returns the value of the record's ipv6_hint param.
    /// Returns None if the record does not have an ipv6_hint param.
    fn get_ipv6_hint_value(&self) -> Option<Vec<AAAA>>;
}

impl HasIpHint for SVCB {
    fn has_ipv4_hint(&self) -> bool {
        self.get_ipv4_hint_value().is_some()
    }

    fn has_ipv6_hint(&self) -> bool {
        self.get_ipv6_hint_value().is_some()
    }

    fn ipv4_hint_contains_address(&self, ip: &Ipv4Addr) -> bool {
        self.get_ipv4_hint_value()
            .filter(|hints| hints.iter().any(|hint| hint.0 == *ip))
            .is_some()
    }

    fn ipv6_hint_contains_address(&self, ip: &Ipv6Addr) -> bool {
        self.get_ipv6_hint_value()
            .filter(|hints| hints.iter().any(|hint| hint.0 == *ip))
            .is_some()
    }
    
    fn get_ipv4_hint_value(&self) -> Option<Vec<A>> {
        self.svc_params()
            .iter()
            .find(|(key, value)| {
                key == &SvcParamKey::Ipv4Hint && value.is_ipv4_hint()
            })
            .map(|(_, value)| value.as_ipv4_hint().unwrap().0.clone())
    }

    fn get_ipv6_hint_value(&self) -> Option<Vec<AAAA>> {
        self.svc_params()
            .iter()
            .find(|(key, value)| {
                key == &SvcParamKey::Ipv6Hint && value.is_ipv6_hint()
            })
            .map(|(_, value)| value.as_ipv6_hint().unwrap().0.clone())
    }
}

pub trait HasAlpn {
    fn has_alpn_param(&self) -> bool;

    /// Determines whether the record has an alpn param and the alpn id is present.
    /// Returns false if the record does not have an alpn param.
    fn has_alpn_id(&self, alpn_id: &str) -> bool;
}

impl HasAlpn for SVCB {
    fn has_alpn_param(&self) -> bool {
        self.svc_params()
            .iter()
            .any(|(key, value)| {
                key == &SvcParamKey::Alpn && value.is_alpn()
            })
    }

    fn has_alpn_id(&self, alpn_id: &str) -> bool {
        self.svc_params()
            .iter()
            .any(|(key, value)| {
                key == &SvcParamKey::Alpn && value.is_alpn() &&
                value.as_alpn().unwrap().0.contains(&alpn_id.to_string())
            })
    }
}

pub trait HasEchConfig {
    /// Returns the value of the record's ech_config param.
    /// Returns None if the record does not have an ech_config param.
    fn get_ech_config(&self) -> Option<Vec<u8>>;
}

impl HasEchConfig for SVCB {
    fn get_ech_config(&self) -> Option<Vec<u8>> {
        self.svc_params()
            .iter()
            .find(|(key, value)| {
                key == &SvcParamKey::EchConfigList && value.is_ech_config_list()
            })
            .map(|(_, value)| value.as_ech_config_list().unwrap().0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use hickory_proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue, IpHint};
    use hickory_proto::rr::domain::Name;

    fn create_svcb_with_ipv4_hint(ipv4_addresses: Vec<Ipv4Addr>) -> SVCB {
        let a_records: Vec<A> = ipv4_addresses.into_iter().map(A::from).collect();
        let svc_params = vec![
            (SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(IpHint(a_records))),
        ];
        let target_name = Name::from_utf8("example.com.").unwrap();
        SVCB::new(1, target_name, svc_params)
    }
    
    fn create_svcb_with_ipv6_hint(ipv6_addresses: Vec<Ipv6Addr>) -> SVCB {
        let aaaa_records: Vec<AAAA> = ipv6_addresses.into_iter().map(AAAA::from).collect();
        let svc_params = vec![
            (SvcParamKey::Ipv6Hint, SvcParamValue::Ipv6Hint(IpHint(aaaa_records))),
        ];
        let target_name = Name::from_utf8("example.com.").unwrap();
        SVCB::new(1, target_name, svc_params)
    }
    
    fn create_svcb_without_hints() -> SVCB {
        let target_name = Name::from_utf8("example.com.").unwrap();
        SVCB::new(1, target_name, Vec::new())
    }

    #[test]
    fn test_ipv4_hint_present() {
        let ipv4_addresses = vec![
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
        ];
        let svcb = create_svcb_with_ipv4_hint(ipv4_addresses.clone());
        
        assert!(svcb.has_ipv4_hint());
        assert!(svcb.get_ipv4_hint_value().is_some());
        
        // Verify the hint contains the expected addresses
        let hint_values = svcb.get_ipv4_hint_value().unwrap();
        assert_eq!(hint_values.len(), 2);
        assert_eq!(hint_values[0].0, ipv4_addresses[0]);
        assert_eq!(hint_values[1].0, ipv4_addresses[1]);
    }

    #[test]
    fn test_ipv6_hint_present() {
        let ipv6_addresses = vec![
            Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334),
            Ipv6Addr::new(0xfe80, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001),
        ];
        let svcb = create_svcb_with_ipv6_hint(ipv6_addresses.clone());
        
        assert!(svcb.has_ipv6_hint());
        assert!(svcb.get_ipv6_hint_value().is_some());
            
        // Verify the hint contains the expected addresses
        let hint_values = svcb.get_ipv6_hint_value().unwrap();
        assert_eq!(hint_values.len(), 2);
        assert_eq!(hint_values[0].0, ipv6_addresses[0]);
        assert_eq!(hint_values[1].0, ipv6_addresses[1]);
    }

    #[test]
    fn test_empty_ip_hints() {
        // Test SVCB records with empty hint lists
        let svcb_empty_ipv4 = create_svcb_with_ipv4_hint(vec![]);
        let svcb_empty_ipv6 = create_svcb_with_ipv6_hint(vec![]);
        
        // Empty hints should still be considered as having hints present
        // but with empty vectors
        assert!(svcb_empty_ipv4.has_ipv4_hint());
        assert!(svcb_empty_ipv4.get_ipv4_hint_value().is_some());
        assert!(svcb_empty_ipv4.get_ipv4_hint_value().unwrap().is_empty());
        
        assert!(svcb_empty_ipv6.has_ipv6_hint());
        assert!(svcb_empty_ipv6.get_ipv6_hint_value().is_some());
        assert!(svcb_empty_ipv6.get_ipv6_hint_value().unwrap().is_empty());
    }

    #[test]
    fn test_no_ip_hints() {
        let svcb = create_svcb_without_hints();
        
        assert!(!svcb.has_ipv4_hint());
        assert!(!svcb.has_ipv6_hint());
        assert!(svcb.get_ipv4_hint_value().is_none());
        assert!(svcb.get_ipv6_hint_value().is_none());
    }
}
