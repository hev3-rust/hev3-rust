use crate::hev3_client::{Hev3Error, Result};
use log::debug;
use quinn::{crypto::rustls::QuicClientConfig, Endpoint};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

//TODO handle ECH, see example https://github.com/rustls/rustls/blob/main/examples/src/bin/ech-client.rs

/// Unified connection type that can hold either a TLS stream or a QUIC connection
/// TODO: add plain TCP connection
#[derive(Debug)]
pub enum Hev3Stream {
    Tls(tokio_rustls::client::TlsStream<tokio::net::TcpStream>),
    Quic(quinn::Connection),
}

pub async fn connect_tcp_tls(
    address: IpAddr,
    port: u16,
    server_name: String,
) -> Result<Hev3Stream> {
    debug!("Starting TCP connection to {}", address);
    let tcp_stream = connect_tcp(address, port).await?;
    debug!("TCP connection established to {}", address);
    let tls_stream = connect_tls(address, server_name, tcp_stream).await?;
    debug!("TLS stream established to {}", address);

    Ok(Hev3Stream::Tls(tls_stream))
}

async fn connect_tcp(address: IpAddr, port: u16) -> Result<TcpStream> {
    TcpStream::connect((address, port)).await.map_err(Hev3Error::map_tcp_error(address))
}

async fn connect_tls(
    address: IpAddr,
    server_name: String,
    stream: TcpStream,
) -> Result<TlsStream<TcpStream>> {
    ensure_crypto_provider();

    let config = create_rustls_client_config();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(server_name).map_err(Hev3Error::map_tls_error(address))?;

    connector.connect(server_name, stream).await.map_err(Hev3Error::map_tls_error(address))
}

pub async fn connect_quic(
    address: IpAddr,
    port: u16,
    server_name: &str,
) -> Result<Hev3Stream> {
    let endpoint = create_quic_endpoint(address)?;
    let server_socket_addr = SocketAddr::new(address, port);

    debug!("Starting QUIC connection to {}", address);
    let connection = endpoint
        .connect(server_socket_addr, server_name)
        .map_err(Hev3Error::map_quic_error(address))?
        .await
        .map_err(Hev3Error::map_quic_error(address))?;
    debug!("QUIC connection established to {}", address);

    Ok(Hev3Stream::Quic(connection))
}

fn create_quic_endpoint(address: IpAddr) -> Result<Endpoint> {
    ensure_crypto_provider();

    let client_ip: IpAddr = match address {
        IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    let client_socket_addr = SocketAddr::new(client_ip, 0);

    let mut endpoint = Endpoint::client(client_socket_addr)
        .map_err(Hev3Error::map_quic_error(address))?;
    endpoint.set_default_client_config(create_quinn_client_config(address)?);

    Ok(endpoint)
}

fn ensure_crypto_provider() {
    if CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

fn create_quinn_client_config(address: IpAddr) -> Result<quinn::ClientConfig> {
    let mut rustls_client_config = create_rustls_client_config();
    rustls_client_config.alpn_protocols.push(b"h3".to_vec()); // TODO: other alpn as well? Make configurable?
    let quic_client_config = QuicClientConfig::try_from(rustls_client_config)
        .map_err(Hev3Error::map_quic_error(address))?;
    
    Ok(quinn::ClientConfig::new(Arc::new(quic_client_config)))
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
