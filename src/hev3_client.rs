use crate::address_collection::ConnectionTargetList;
use crate::connection::Hev3Stream;
use crate::{address_sorting, dns, racing};
use hickory_resolver::{Resolver, TokioResolver};
use pnet::datalink;
use rustls::lock::Mutex;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Duration;

pub use crate::errors::Hev3Error;

pub type Result<T> = std::result::Result<T, Hev3Error>;

static IPV6_AVAILABLE: LazyLock<Mutex<bool>> = LazyLock::new(|| Mutex::new(true));
pub fn is_ipv6_available() -> bool {
    *IPV6_AVAILABLE.lock().unwrap()
}

// TODO: Builder?
#[derive(Debug, Clone)]
pub struct Hev3Config {
    pub resolution_delay: Duration,
    pub connection_attempt_delay: Duration,
    pub connection_timeout: Duration,
    pub preferred_address_family_count: u8,
    pub use_svcb_instead_of_https: bool,
    pub max_svcb_aliases_to_follow: u8,
}

impl Default for Hev3Config {
    fn default() -> Self {
        Self {
            resolution_delay: Duration::from_millis(50),
            connection_attempt_delay: Duration::from_millis(250),
            connection_timeout: Duration::from_secs(20),
            preferred_address_family_count: 1,
            use_svcb_instead_of_https: false,
            max_svcb_aliases_to_follow: 2,
        }
    }
}

pub struct Hev3 {
    config: Hev3Config,
    resolver: TokioResolver,
}

impl Hev3 {
    pub fn new(config: Hev3Config) -> Result<Self> {
        let resolver = Resolver::builder_tokio()?.build();
        Ok(Self { config, resolver })
    }

    pub fn with_resolver(config: Hev3Config, resolver: TokioResolver) -> Self {
        Self { config, resolver }
    }

    pub async fn connect(&self, hostname: &str, port: u16) -> Result<Hev3Stream> {
        check_ipv6_available();

        let mut dns_resolver = dns::init_queries(
            &self.resolver,
            hostname,
            self.config.use_svcb_instead_of_https,
            self.config.max_svcb_aliases_to_follow,
        );

        let initial_dns_results = dns::wait_for_dns_results(
            &mut dns_resolver.rx,
            self.config.resolution_delay
        ).await?;

        let mut connection_targets = ConnectionTargetList::new(initial_dns_results);
        address_sorting::sort_addresses(
            &mut connection_targets,
            self.config.preferred_address_family_count,
        );

        racing::race_connections(connection_targets, hostname, port, dns_resolver, &self.config)
            .await
    }
}

fn check_ipv6_available() {
    let mut ipv6 = IPV6_AVAILABLE.lock().unwrap();
    *ipv6 = datalink::interfaces().iter()
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
