use crate::hev3_client::{Hev3Error, Result};
use hickory_proto::rr::{
    rdata::{
        https::HTTPS,
        svcb::{IpHint, SvcParamKey, SvcParamValue, SVCB},
        A, AAAA,
    },
    RData, Record, RecordType
};
use hickory_resolver::{lookup::Lookup, TokioResolver};
use log::{debug, info, warn};
use pnet::datalink;
use rand::seq::IndexedRandom;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Quic,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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

#[derive(Debug)]
pub enum DnsResult {
    // The Vec should always contain records of the same type. However, this is not enforced currently.
    PositiveDnsResult(Vec<Record>),
    NegativeDnsResult(RecordType),
}

pub struct DnsResolver {
    pub rx: Receiver<DnsResult>,
    pub handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

////////////////////////////////////////////////////////////////////////////////
// DNS resolution logic
////////////////////////////////////////////////////////////////////////////////

struct LookupContext {
    resolver: Arc<TokioResolver>,
    hostname: String,
    tx: Sender<DnsResult>,
    task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    use_svcb_instead_of_https: bool,
    previous_lookups: Arc<Mutex<Vec<(String, RecordType)>>>,
}

impl Clone for LookupContext {
    fn clone(&self) -> Self {
        Self {
            resolver: self.resolver.clone(),
            hostname: self.hostname.clone(),
            tx: self.tx.clone(),
            task_handles: self.task_handles.clone(),
            use_svcb_instead_of_https: self.use_svcb_instead_of_https,
            previous_lookups: self.previous_lookups.clone(),
        }
    }
}

pub fn init_queries(
    resolver: &TokioResolver,
    hostname: &str,
    use_svcb_instead_of_https: bool,
) -> DnsResolver {
    let (tx, rx) = tokio::sync::mpsc::channel(32);

    let task_handles = Arc::new(Mutex::new(Vec::new()));

    let context = LookupContext {
        resolver: Arc::new(resolver.clone()),
        hostname: hostname.to_string(),
        tx,
        task_handles: task_handles.clone(),
        use_svcb_instead_of_https,
        previous_lookups: Arc::new(Mutex::new(Vec::new())),
    };

    // TODO: when IPv4 only, then dont send AAAA query
    let svcb_type = get_svcb_type(use_svcb_instead_of_https);
    start_dns_lookup_concurrently(svcb_type, &context);
    start_dns_lookup_concurrently(RecordType::AAAA, &context);
    start_dns_lookup_concurrently(RecordType::A, &context);

    DnsResolver {
        rx,
        handles: task_handles,
    }
}

fn start_dns_lookup_concurrently(record_type: RecordType, context: &LookupContext) {
    let task_handles = context.task_handles.clone();
    let context = context.clone();

    let handle = tokio::spawn(async move {
        if save_in_previous_lookups(record_type, &context).is_err() {
            return;
        }

        debug!("Starting {} lookup for {}", record_type, context.hostname);

        match context.resolver.lookup(&context.hostname, record_type).await {
            Ok(lookup) => handle_successful_lookup(lookup, &context).await,
            Err(e) => {
                info!("DNS resolution error for {}: {:?}", record_type, e.to_string());
                // TODO: do the following only if "no records found". Other errors might have to be handled differently.
                let negative_result = DnsResult::NegativeDnsResult(record_type);
                context.tx.send(negative_result).await.unwrap();
            }
        }
    });

    task_handles.lock().unwrap().push(handle);
}

fn save_in_previous_lookups(
    record_type: RecordType,
    context: &LookupContext,
) -> std::result::Result<(), ()> {
    let mut previous_lookups = context.previous_lookups.lock().unwrap();
    if previous_lookups.contains(&(context.hostname.clone(), record_type)) {
        return Err(());
    }
    previous_lookups.push((context.hostname.clone(), record_type));
    Ok(())
}

async fn handle_successful_lookup(lookup: Lookup, context: &LookupContext) {
    if lookup.records().is_empty() {
        debug!("Empty {} RRset for {}", lookup.query().query_type(), lookup.query().name());
        let negative_result = DnsResult::NegativeDnsResult(lookup.query().query_type());
        context.tx.send(negative_result).await.unwrap();
        return;
    }

    let mut address_records = Vec::new();
    let mut svcb_records = Vec::new();

    for record in lookup.records() {
        debug!("Received {} record: \"{}\", ttl: {}, rdata: {:?}", 
            record.record_type(), record.name().to_utf8(), record.ttl(), record.data());
        match record.data() {
            RData::A(_) | RData::AAAA(_) => {
                address_records.push(record.clone());
            }
            RData::HTTPS(_) | RData::SVCB(_) => {
                svcb_records.push(record.clone());
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
    if !address_records.is_empty() {
        context.tx.send(DnsResult::PositiveDnsResult(address_records)).await.unwrap();
    }
    if !svcb_records.is_empty() {
        handle_svcb_records(svcb_records, context).await;
    }
}

async fn handle_svcb_records(svcb_records: Vec<Record>, context: &LookupContext) {
    // Check if any records are in alias mode (priority 0)
    let alias_records: Vec<&SVCB> = svcb_records
        .iter()
        .map(|r| {
            match r.data() {
                RData::HTTPS(HTTPS(svcb)) | RData::SVCB(svcb) => svcb,
                _ => panic!("Expected HTTPS/SVCB record, got {:?}", r.data()),
            }
        })
        .filter(|r| r.svc_priority() == 0)
        .collect();

    // If we have alias records, ignore any service mode records [RFC 9460].
    // Otherwise, send all records over the DnsResult channel.
    if !alias_records.is_empty() {
        handle_svcb_alias_mode_records(alias_records, context);
    } else {
        resolve_alternative_target_names(&svcb_records, context);
        context.tx.send(DnsResult::PositiveDnsResult(svcb_records)).await.unwrap();
    }
}

/// Chooses one target name randomly from the alias records and resolves it [RFC 9460]
fn handle_svcb_alias_mode_records(alias_records: Vec<&SVCB>, context: &LookupContext) {
    if let Some(record) = alias_records.choose(&mut rand::rng()) {
        if record.target_name().is_root() {
            // RFC 9460, Section 2.5.1:
            // "For AliasMode SVCB RRs, a TargetName of "." indicates that the service is not
            // available or does not exist. This indication is advisory: clients encountering this
            // indication **MAY** ignore it and attempt to connect without the use of SVCB."
            // We choose to ignore it here, because this is the easiest way to handle it.
            debug!("Ignoring AliasMode SVCB record with TargetName '.' for {}.", context.hostname);
            return;
        }

        let mut new_context = context.clone();
        new_context.hostname = record.target_name().to_utf8();

        // TODO loop detection
        // TODO in case of an alias chain, start A/AAAA lookups for the last alias name
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

fn resolve_alternative_target_names(svcb_records: &Vec<Record>, context: &LookupContext) {
    for record in svcb_records {
        let svcb = match record.data() {
            RData::HTTPS(HTTPS(svcb)) | RData::SVCB(svcb) => svcb,
            _ => panic!("Expected HTTPS/SVCB record, got {:?}", record.data()),
        };

        let mut new_context = context.clone();
        if !svcb.target_name().is_root() {
            new_context.hostname = svcb.target_name().to_utf8();
        }
    
        start_dns_lookup_concurrently(RecordType::AAAA, &new_context);
        start_dns_lookup_concurrently(RecordType::A, &new_context);
    }
}

////////////////////////////////////////////////////////////////////////////////
// Waiting for DNS results
////////////////////////////////////////////////////////////////////////////////

/// Wait for DNS results according to HEv3 specification Section 4.2
/// The client moves onto sorting addresses and establishing connections once:
/// 
/// Either:
/// * Some positive (non-empty) address answers have been received AND
/// * A positive (non-empty) or negative (empty) answer has been received for the preferred address family AND
/// * SVCB/HTTPS service information has been received (or has received a negative response)
/// 
/// Or:
/// * Some positive (non-empty) address answers have been received AND
/// * A resolution time delay has passed after which other answers have not been received
pub async fn wait_for_dns_results(
    rx: &mut Receiver<DnsResult>,
    resolution_delay: Duration,
) -> Result<Vec<DnsResult>> {
    let mut dns_results = Vec::new();

    // If IPv6 is available, prefer it over IPv4.
    let ipv6_preferred = is_ipv6_available();
    // TODO: if neither ipv4 nor ipv6 are available, return an NoRouteAvailable error?

    // Wait for first answer that contains an address
    let dns_results_received_until_first_address = wait_for_first_address(rx).await?;
    dns_results.extend(dns_results_received_until_first_address);

    let mut preferred_family_result_received = false;
    let mut svcb_result_received = false;

    for result in &dns_results {
        preferred_family_result_received |= is_preferred_family_result(result, ipv6_preferred);
        svcb_result_received |= is_svcb_result(result);
    }

    // If any of the initial results already satisfy our conditions, return immediately
    if preferred_family_result_received && svcb_result_received {
        debug!("Received an answer for the preferred family and SVCB/HTTPS, \
                continue to address sorting");
        return Ok(dns_results);
    }

    let delay_future = tokio::time::sleep(resolution_delay);
    tokio::pin!(delay_future);

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Some(dns_result) => {
                        preferred_family_result_received |= is_preferred_family_result(&dns_result, 
                            ipv6_preferred);
                        svcb_result_received |= is_svcb_result(&dns_result);
                        
                        dns_results.push(dns_result);
                        
                        if preferred_family_result_received && svcb_result_received {
                            debug!("Received an answer for the preferred family and SVCB/HTTPS, \
                                    continue to address sorting"); // TODO measure time
                            return Ok(dns_results);
                        }
                    }
                    None => {
                        // All DNS queries have completed, return what we have
                        debug!("All DNS queries have completed, continue to address sorting");
                        return Ok(dns_results);
                    }
                }
            }
            // Resolution delay timeout (condition set 2)
            _ = &mut delay_future => {
                debug!("Resolution delay timeout, continue to address sorting");
                return Ok(dns_results);
            }
        }
    }
}

fn is_ipv6_available() -> bool {
    datalink::interfaces().iter()
        .filter(|interface| interface.is_up() && !interface.is_loopback())
        .flat_map(|interface| interface.ips.iter())
        .any(|ip| {
            match ip.ip() {
                IpAddr::V6(ip) => {
                    !ip.is_unicast_link_local() && !ip.is_loopback() && !ip.is_unspecified()
                }
                _ => false,
            }
        })
}

async fn wait_for_first_address(rx: &mut Receiver<DnsResult>) -> Result<Vec<DnsResult>> {
    let mut dns_results = Vec::new();

    loop {
        let dns_result = match rx.recv().await {
            Some(first_dns_result) => first_dns_result,
            None => {
                warn!("No addresses found");
                return Err(Hev3Error::NoAddressesFound)
            }
        };

        let first_address_received = has_address(&dns_result);

        dns_results.push(dns_result);
        
        if first_address_received {
            break;
        }
    }

    Ok(dns_results)
}

fn has_address(dns_result: &DnsResult) -> bool {
    if let DnsResult::PositiveDnsResult(positive_dns_result) = dns_result {
        positive_dns_result.iter().any(|record| {
            match record.data() {
                RData::A(_) | RData::AAAA(_) => true,
                RData::HTTPS(HTTPS(svcb)) | RData::SVCB(svcb) => {
                    svcb.has_ipv6_hint() || svcb.has_ipv4_hint()
                },
                _ => false,
            }
        })
    } else {
        false
    }
}

/// Returns true if the DNS result:
/// - contains a record (A/AAAA) for the preferred family, or
/// - is a NegativeDnsResult for the preferred family's query (A/AAAA), or
/// - contains an SVCB/HTTPS record with an iphint param for the preferred family.
fn is_preferred_family_result(
    dns_result: &DnsResult,
    ipv6_preferred: bool,
) -> bool {
    match dns_result {
        DnsResult::PositiveDnsResult(positive_dns_result) => {
            positive_dns_result.iter().any(|record| {   
                match record.data() {
                    RData::AAAA(_) => ipv6_preferred,
                    RData::A(_) => !ipv6_preferred,
                    RData::HTTPS(HTTPS(svcb)) | RData::SVCB(svcb) => {
                        if ipv6_preferred {
                            svcb.has_ipv6_hint()
                        } else {
                            svcb.has_ipv4_hint()
                        }
                    }
                    _ => false,
                }
            })
        }
        DnsResult::NegativeDnsResult(record_type) => {
            (*record_type == RecordType::AAAA && ipv6_preferred)
            || (*record_type == RecordType::A && !ipv6_preferred)
        }
    }
}

fn is_svcb_result(dns_result: &DnsResult) -> bool {
    match dns_result {
        DnsResult::PositiveDnsResult(records) => {
            records.iter().any(|record| {
                matches!(record.record_type(), RecordType::SVCB | RecordType::HTTPS)
            })
        }
        DnsResult::NegativeDnsResult(record_type) => {
            matches!(record_type, RecordType::SVCB | RecordType::HTTPS)
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
            .find_map(|(key, value)| match (key, value) {
                (SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(IpHint(ips))) => Some(ips.clone()),
                _ => None,
            })
    }

    fn get_ipv6_hint_value(&self) -> Option<Vec<AAAA>> {
        self.svc_params()
            .iter()
            .find_map(|(key, value)| match (key, value) {
                (SvcParamKey::Ipv6Hint, SvcParamValue::Ipv6Hint(IpHint(ips))) => Some(ips.clone()),
                _ => None,
            })
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
            .any(|(key, value)| key == &SvcParamKey::Alpn && value.is_alpn())
    }

    fn has_alpn_id(&self, alpn_id: &str) -> bool {
        self.svc_params().iter().any(|(key, value)| {
            key == &SvcParamKey::Alpn
                && value.is_alpn()
                && value.as_alpn().unwrap().0.contains(&alpn_id.to_string())
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
            .find_map(|(key, value)| match (key, value) {
                (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(ech_config)) => {
                    Some(ech_config.0.clone())
                }
                _ => None,
            })
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
