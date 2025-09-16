use hev3_rust::{Hev3, Hev3Config, Hev3Stream};
use log::{error, info, LevelFilter};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain = get_domain_from_args();
    init_logger();
    
    let config = Hev3Config::default();
    let hev3 = Hev3::new(config)?;
    
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