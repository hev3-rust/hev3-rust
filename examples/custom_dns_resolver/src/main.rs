use hev3_rust::{Hev3, Hev3Config, Hev3Stream};
use log::{error, info, LevelFilter};
use std::env;
use hickory_resolver::Resolver;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use rustls::crypto::CryptoProvider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain = get_domain_from_args();
    init_logger();
    
    let config = Hev3Config::default();

    // Use only one of the ResolverConfigs below!
    
    // plain DNS
    // let resolver_config = ResolverConfig::cloudflare();
    // let resolver_config = ResolverConfig::google();
    // let resolver_config = ResolverConfig::quad9();
    
    // DoT; enable feature 'tls-aws-lc-rs' for hickory-resolver in Cargo.toml
    let resolver_config = ResolverConfig::cloudflare_tls();
    // let resolver_config = ResolverConfig::google_tls();
    // let resolver_config = ResolverConfig::quad9_tls();

    // DoH; enable feature 'https-aws-lc-rs' for hickory-resolver in Cargo.toml
    // let resolver_config = ResolverConfig::cloudflare_https();
    // let resolver_config = ResolverConfig::google_https();
    // let resolver_config = ResolverConfig::quad9_https();

    // DoH3; enable feature 'h3-aws-lc-rs' for hickory-resolver in Cargo.toml
    // let resolver_config = ResolverConfig::google_h3();

    if CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    let resolver = Resolver::builder_with_config(
        resolver_config,
        TokioConnectionProvider::default(),
    ).build();
    let hev3 = Hev3::with_resolver(config, resolver);
    
    info!("Connecting to {}", domain);
    let stream = hev3.connect(&domain, 443).await;
    match stream {
        Ok(Hev3Stream::Tls(_)) => {
            // The stream is closed automatically when out of scope
        }
        Ok(Hev3Stream::Quic(stream)) => {
            stream.close((0 as u32).into(), &[]);
        }
        Err(e) => {
            error!("Could not connect to {}: {}", domain, e);
        }
    }
    
    Ok(())
}

fn get_domain_from_args() -> String {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("No domain provided");
        eprintln!("Usage: {} <domain>", args[0]);
        std::process::exit(1);
    }
    args[1].clone()
}

fn init_logger() {
    env_logger::builder()
        .format_timestamp_millis()
        .filter(Some("hev3_rust"), LevelFilter::Debug)
        .init();
}
