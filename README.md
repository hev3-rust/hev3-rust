# Happy Eyeballs Version 3 (HEv3) in Rust

This is a Rust implementation of the Happy Eyeballs Version 3 algorithm, which helps reduce user-visible delays on dual-stack hosts by racing connections to resolved addresses while preferring IPv6.

## Status

This repo is under development and **not ready to be used** in any other than academic environments. 

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
        preferred_protocol_combination_count: 1,
        use_svcb_instead_of_https: false,
    };
    [...]
```

## Configuration

The `Hev3Config` struct allows you to customize the behavior:

- `resolution_delay`: Time to wait for AAAA records before proceeding with IPv4
- `connection_attempt_delay`: Time to wait for a connection attempt before starting the next
- `connection_timeout`: Maximum time to wait for connection establishment
- `preferred_protocol_combination_count`: Number of addresses to try before switching protocol families
- `use_svcb_instead_of_https`: By default, hev3-rust resolves HTTPS RRs. This option can be used to tell hev3-rust to issue SVCB queries instead.
