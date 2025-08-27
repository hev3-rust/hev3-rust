# Happy Eyeballs Version 3 (HEv3) in Rust

This is a Rust implementation of the Happy Eyeballs Version 3 algorithm, which helps reduce user-visible delays on dual-stack hosts by racing connections to resolved addresses while preferring IPv6.

This project is an implementation of the current draft of Happy Eyeballs Version 3, as outlined in [draft-ietf-happy-happyeyeballs-v3-01](https://datatracker.ietf.org/doc/draft-ietf-happy-happyeyeballs-v3/01/). The implementation is primarily focused on handling HTTP/HTTPS traffic, but should work for other application-layer protocols as well as it returns raw TCP+TLS or QUIC streams.

Like the HEv3 specification draft, this implementation assumes a preference for IPv6 and QUIC during connection racing. This preference is currently not configurable. 

## Status

This repo is under development and maily aimed at research purposes. It is **not ready** for production use.

The following parts of the HEv3 specification draft are currently not implemented:
- handling of multiple dns servers (IPv4/IPv6).
- history of round-trip-times to influence target sorting
- flexible timeouts and delays
- TODO: destination address selection (MUST)
- TODO: SVCB-reliant clients MUST wait for SVCB records before proceeding with the cryptographic handshake
- TODO: handle expired DNS records: remove ConnectionTarget if used == false
- TODO: everything in Section 8 (Supporting IPv6-Mostly and IPv6-Only Networks)

## Usage

With default configuration:

```rust
use hev3_rust::{Hev3, Hev3Config};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Hev3Config::default();
    let hev3 = Hev3::new(config)?;
    
    // Try to connect to a host
    match hev3.connect("www.example.com", 80).await {
        Ok(stream) => {
            println!("Successfully connected!");
            // Use the stream...
        }
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
        }
    }
    
    Ok(())
}
```

Define a custom configuration:

```rust
    [...]
    // Instead of:
    // let config = Hev3Config::default();
    // use:
    let config = Hev3Config {
        resolution_delay: Duration::from_millis(50),
        connection_attempt_delay: Duration::from_millis(250),
        connection_timeout: Duration::from_secs(5),
        preferred_address_family_count: 1,
        use_svcb_instead_of_https: false,
    };
    [...]
```

## Configuration

The `Hev3Config` struct allows you to customize the behavior:

- `resolution_delay`: Time to wait for AAAA records before proceeding with IPv4
- `connection_attempt_delay`: Time to wait for a connection attempt before starting the next
- `connection_timeout`: Maximum time to wait for connection establishment
- `preferred_address_family_count`: Number of IPv6 addresses to try before starting an IPv4 connection attempt
- `use_svcb_instead_of_https`: By default, hev3-rust resolves HTTPS RRs. This option can be used to tell hev3-rust to issue SVCB queries instead.
