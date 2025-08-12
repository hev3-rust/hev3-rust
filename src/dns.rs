use crate::hev3_client::{Hev3Error, Result};
use hickory_proto::rr::{
    rdata::{
        https::HTTPS,
        svcb::{SvcParamKey, SVCB},
        A, AAAA,
    },
    RData, RecordType,
};
use hickory_resolver::{lookup::Lookup, TokioResolver};
use log::{debug, info, warn};
use rand::seq::IndexedRandom;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};
use tokio::sync::mpsc::{Receiver, Sender};

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

////////////////////////////////////////////////////////////////////////////////
// DNS resolution logic
////////////////////////////////////////////////////////////////////////////////

struct LookupContext {
    resolver: Arc<TokioResolver>,
    hostname: String,
    tx: Sender<DnsResult>,
    use_svcb_instead_of_https: bool,
}

impl Clone for LookupContext {
    fn clone(&self) -> Self {
        Self {
            resolver: self.resolver.clone(),
            hostname: self.hostname.clone(),
            tx: self.tx.clone(),
            use_svcb_instead_of_https: self.use_svcb_instead_of_https,
        }
    }
}

pub fn init_queries(
    resolver: &TokioResolver,
    hostname: &str,
    use_svcb_instead_of_https: bool,
) -> Receiver<DnsResult> {
    let (tx, rx) = tokio::sync::mpsc::channel(32);

    let context = LookupContext {
        resolver: Arc::new(resolver.clone()),
        hostname: hostname.to_string(),
        tx,
        use_svcb_instead_of_https,
    };

    let svcb_type = get_svcb_type(use_svcb_instead_of_https);
    start_dns_lookup_concurrently(svcb_type, &context);
    start_dns_lookup_concurrently(RecordType::AAAA, &context);
    start_dns_lookup_concurrently(RecordType::A, &context);

    rx
}

fn start_dns_lookup_concurrently(
    record_type: RecordType,
    context: &LookupContext,
) {
    let context = context.clone();

    tokio::spawn(async move {
        let result = context.resolver.lookup(&context.hostname, record_type).await;

        match result {
            Ok(lookup) => handle_successful_lookup(lookup, &context).await,
            Err(e) => {
                // TODO: handle errors more appropriately
                // "no records found" is acceptable, maybe no logging needed?
                // others might be a problem - panic?
                info!("DNS resolution error: {:?}", e.to_string());
            }
        }
    });
}

async fn handle_successful_lookup(
    lookup: Lookup, 
    context: &LookupContext,
) {
    if lookup.records().is_empty() {
        debug!("Empty {} RRset for {}", lookup.query().query_type(), lookup.query().name());
        return;
    }

    let mut svcb_records = Vec::new();

    for record in lookup.records() {
        debug!("Received DNS record: {:?}", record);
        match record.data() {
            RData::A(_) | RData::AAAA(_) => {
                let dns_result = DnsResult {
                    domain: record.name().to_utf8(),
                    record: record.data().clone(),
                };
                context.tx.send(dns_result).await.unwrap();
            }
            RData::HTTPS(HTTPS(svcb)) | RData::SVCB(svcb) => {
                // SVCB/HTTPS records are handled in bulk
                svcb_records.push((record.name().to_utf8(), svcb));
            }
            RData::CNAME(_) => {
                // CNAME records are handled by hickory_resolver, so the records for the
                // canonical name should already be in the record list.
            }
            _ => {
                info!("Unknown record: {:?}", record);
            }
        }
    }
    handle_svcb_records(svcb_records, context).await;
}

async fn handle_svcb_records(
    svcb_records: Vec<(String, &SVCB)>, 
    context: &LookupContext,
) {
    // Check if any records are in alias mode (priority 0)
    let alias_records: Vec<&SVCB> = svcb_records
        .iter()
        .filter(|r| r.1.svc_priority() == 0)
        .map(|r| r.1)
        .collect();

    // If we have alias records, ignore any service mode records [RFC 9460].
    // Otherwise, send all records over the DnsResult channel.
    if !alias_records.is_empty() {
        handle_svcb_alias_mode_records(alias_records, context);
    } else {
        for record in svcb_records.into_iter() {
            let dns_result = create_dns_result_from_svcb_record(record.0, record.1, context);
            context.tx.send(dns_result).await.unwrap();
        }
    }
}

/// Chooses one target name randomly from the alias records and resolves it [RFC 9460]
fn handle_svcb_alias_mode_records(
    alias_records: Vec<&SVCB>, 
    context: &LookupContext,
) {
    if let Some(record) = alias_records.choose(&mut rand::rng()) {
        let mut new_context = context.clone();
        new_context.hostname = record.target_name().to_utf8();

        // TODO loop detection.
        start_dns_lookup_concurrently(
            get_svcb_type(context.use_svcb_instead_of_https),
            &new_context,
        );
    }
}

fn get_svcb_type(use_svcb_instead_of_https: bool) -> RecordType {
    if use_svcb_instead_of_https {
        RecordType::SVCB
    } else {
        RecordType::HTTPS
    }
}

fn create_dns_result_from_svcb_record(
    hostname: String,
    record: &SVCB, 
    context: &LookupContext,
) -> DnsResult {
    let rdata = if context.use_svcb_instead_of_https {
        RData::SVCB(record.clone())
    } else {
        RData::HTTPS(HTTPS(record.clone()))
    };
    
    DnsResult {
        domain: hostname,
        record: rdata,
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
    resolution_delay: Duration,
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
            Ok(first_dns_result)
        }
        None => {
            warn!("No addresses found");
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
    use hickory_proto::rr::domain::Name;
    use hickory_proto::rr::rdata::svcb::{IpHint, SvcParamKey, SvcParamValue};
    use std::net::{Ipv4Addr, Ipv6Addr};

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
