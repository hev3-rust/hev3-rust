use crate::hev3_client::{Hev3Error, Result};
use log::debug;
use quinn::{crypto::rustls::QuicClientConfig, Endpoint};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

//TODO handle ECH, see example https://github.com/rustls/rustls/blob/main/examples/src/bin/ech-client.rs

/// Unified connection type that can hold either a TLS stream or a QUIC connection
/// TODO: add plain TCP connection
#[derive(Debug)]
pub enum Hev3Stream {
    Tls(tokio_rustls::client::TlsStream<tokio::net::TcpStream>),
    Quic(quinn::Connection),
}

pub async fn connect_tcp_tls(address: IpAddr, server_name: String, port: u16) -> Result<Hev3Stream> {
    ensure_crypto_provider();

    let config = create_rustls_client_config();

    let connector = TlsConnector::from(Arc::new(config));
    debug!("Starting TCP connection to {}", address); // TODO measure time
    let stream = TcpStream::connect((address, port)).await.map_err(Hev3Error::tcp_error)?;
    debug!("TCP connection established to {}", address);
    let server_name = ServerName::try_from(server_name).map_err(Hev3Error::tls_error)?;
    let tls_stream = connector.connect(server_name, stream).await.map_err(Hev3Error::tls_error)?;
    debug!("TLS stream established to {}", address);

    Ok(Hev3Stream::Tls(tls_stream))
} 

pub async fn connect_quic(address: IpAddr, server_name: &str, port: u16) -> Result<Hev3Stream> {
    ensure_crypto_provider();

    let client_config = create_quinn_client_config()?;

    let client_ip: IpAddr = match address {
        IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    let client_socket_addr = SocketAddr::new(client_ip, 0);

    let mut endpoint = Endpoint::client(client_socket_addr).map_err(Hev3Error::quic_error)?;
    endpoint.set_default_client_config(client_config);

    let server_socket_addr = SocketAddr::new(address, port);

    debug!("Starting QUIC connection to {}", address); // TODO measure time
    let connection = endpoint.connect(server_socket_addr, server_name)?.await?;
    debug!("QUIC connection established to {}", address);
    
    Ok(Hev3Stream::Quic(connection))
}

fn ensure_crypto_provider() {
    if CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

fn create_rustls_client_config() -> rustls::ClientConfig {
    // TODO: probably use OS's root certs
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

fn create_quinn_client_config() -> Result<quinn::ClientConfig> {
    let mut rustls_client_config = create_rustls_client_config();
    rustls_client_config.alpn_protocols.push(b"h3".to_vec()); // TODO: other alpn as well? Make configurable?
    Ok(quinn::ClientConfig::new(
        Arc::new(
            QuicClientConfig::try_from(rustls_client_config).map_err(Hev3Error::quic_error)?
        )
    ))
}
