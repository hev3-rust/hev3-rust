use crate::address_collection::ConnectionTargetList;
use crate::connection::Hev3Stream;
use crate::{address_sorting, dns, racing};
use hickory_resolver::{Resolver, TokioResolver};
use std::time::Duration;

pub use crate::errors::Hev3Error;

pub type Result<T> = std::result::Result<T, Hev3Error>;

// TODO: Builder?
#[derive(Debug, Clone)]
pub struct Hev3Config {
    pub resolution_delay: Duration,
    pub connection_attempt_delay: Duration,
    pub connection_timeout: Duration,
    pub preferred_address_family_count: usize,
    pub use_svcb_instead_of_https: bool,
}

impl Default for Hev3Config {
    fn default() -> Self {
        Self {
            resolution_delay: Duration::from_millis(50),
            connection_attempt_delay: Duration::from_millis(250),
            connection_timeout: Duration::from_secs(20),
            preferred_address_family_count: 1,
            use_svcb_instead_of_https: false,
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
        let mut dns_resolver = dns::init_queries(
            &self.resolver,
            hostname,
            self.config.use_svcb_instead_of_https,
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
