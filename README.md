# Happy Eyeballs Version 3 (HEv3) in Rust

This is a Rust implementation of the Happy Eyeballs Version 3 algorithm, which helps reduce user-visible delays on dual-stack hosts by racing connections to resolved addresses while preferring IPv6.

This project is an implementation of the current draft of Happy Eyeballs Version 3, as outlined in [draft-ietf-happy-happyeyeballs-v3-02](https://datatracker.ietf.org/doc/draft-ietf-happy-happyeyeballs-v3/02/). The implementation is primarily focused on handling HTTP/HTTPS traffic, but should work for other application-layer protocols as well as it returns raw TCP+TLS or QUIC streams.

Like the HEv3 specification draft, this implementation assumes a preference for IPv6 and QUIC during connection racing. This preference is currently not configurable. 

If you use this code for a scientific publication, please cite this repository according to [CITATION.cff](CITATION.cff).

## Status

This repo is under development and maily aimed at research purposes. It is **not ready** for production use.

The following parts of the HEv3 specification draft are currently not implemented:
- handling of multiple dns servers (IPv4/IPv6).
- history of round-trip-times to influence target sorting
- flexible timeouts and delays
- proper Destination Address Selection
- pending TLS and QUIC handshakes until SVCB queries arrive when DoE is used
- handling A/AAAA DNS records that expired before the corresponding IP addres has been attempted
- support for IPv6-mostly and IPv6-only networks

## Usage

Include the `hev3-rust` crate in your Cargo.toml:

```toml
[dependencies]
hev3-rust = { git = "https://github.com/hev3-rust/hev3-rust.git" }
```

To use the default configuration copy the following into your main.rs:

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

Or define a custom configuration:

```rust
    // Instead of:
    // let config = Hev3Config::default();
    // use:
    let config = Hev3Config {
        resolution_delay: Duration::from_millis(50),
        connection_attempt_delay: Duration::from_millis(250),
        connection_timeout: Duration::from_secs(5),
        preferred_address_family_count: 1,
        use_svcb_instead_of_https: false,
        max_svcb_aliases_to_follow: 2,
    };
```

Or override only parts of the default configuration. For example, to only override the Connection Attempt Delay:

```rust
    // Instead of:
    // let config = Hev3Config::default();
    // use:
    let config = Hev3Config {
        connection_attempt_delay: Duration::from_millis(200),
        ..Hev3Config::default()
    };
```

Also, have a look at the `examples` folder.

## Configuration

The `Hev3Config` struct allows you to customize the behavior:

- `resolution_delay`: Time to wait for AAAA and SVCB/HTTPS records before proceeding (default: 50ms)
- `connection_attempt_delay`: Time to wait for a connection attempt before starting the next (default: 250ms)
- `connection_timeout`: Maximum time to wait for connection establishment (default: 20s)
- `preferred_address_family_count`: Number of IPv6 addresses to try before starting an IPv4 connection attempt (default: 1)
- `use_svcb_instead_of_https`: Issue SVCB queries instead of HTTPS. By default, hev3-rust resolves HTTPS RRs (default: false)
- `max_svcb_aliases_to_follow`: Maximum number of chained SVCB alias records to follow when resolving service bindings (default: 2)

## Compiling the library

Make sure you have the rust compiler and cargo installed, as described here: https://www.rust-lang.org/tools/install

Then, in the repo directory, run

```sh
cargo build
```

or 

```sh
cargo build --release
```

to build with release optimizations.
