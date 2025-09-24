use crate::hev3_client::{Hev3Error, Result, get_native_certs};
use crate::dns::EchConfigList;
use log::{debug, info, trace};
use quinn::{crypto::rustls::QuicClientConfig, Endpoint};
use rustls::{
    ConfigBuilder, WantsVerifier,
    client::{EchConfig, EchMode}, 
    crypto::CryptoProvider, 
    pki_types::{EchConfigListBytes, ServerName}, 
};
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

//TODO handle ECH, see example https://github.com/rustls/rustls/blob/main/examples/src/bin/ech-client.rs

/// Unified connection type that can hold either a TLS stream or a QUIC connection
#[derive(Debug)]
pub enum Hev3Stream {
    Tls(tokio_rustls::client::TlsStream<tokio::net::TcpStream>),
    Quic(quinn::Connection),
}

pub async fn connect_tcp_tls(
    address: IpAddr,
    port: u16,
    server_name: String,
    ech_config: Option<EchConfigList>,
) -> Result<Hev3Stream> {
    debug!("Starting TCP connection to {}", address);
    let tcp_stream = connect_tcp(address, port).await?;
    debug!("TCP connection established to {}", address);
    let tls_stream = connect_tls(address, server_name, tcp_stream, ech_config).await?;
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
    ech_config: Option<EchConfigList>,
) -> Result<TlsStream<TcpStream>> {
    ensure_crypto_provider();

    let config = create_tls_config(ech_config).map_err(Hev3Error::map_tls_error(address))?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(server_name).map_err(Hev3Error::map_tls_error(address))?;

    connector.connect(server_name, stream).await.map_err(Hev3Error::map_tls_error(address))
}

pub async fn connect_quic(
    address: IpAddr,
    port: u16,
    server_name: &str,
    ech_config: Option<EchConfigList>,
) -> Result<Hev3Stream> {
    let endpoint = create_quic_endpoint(address, ech_config)?;
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

fn create_quic_endpoint(address: IpAddr, ech_config: Option<EchConfigList>) -> Result<Endpoint> {
    ensure_crypto_provider();

    let client_ip: IpAddr = match address {
        IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    let client_socket_addr = SocketAddr::new(client_ip, 0);

    let mut endpoint = Endpoint::client(client_socket_addr)
        .map_err(Hev3Error::map_quic_error(address))?;
    endpoint.set_default_client_config(create_quinn_client_config(address, ech_config)?);

    Ok(endpoint)
}

fn ensure_crypto_provider() {
    if CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

fn create_quinn_client_config(
    address: IpAddr, 
    ech_config: Option<EchConfigList>
) -> Result<quinn::ClientConfig> {
    let mut tls_config = create_tls_config(ech_config)
        .map_err(Hev3Error::map_tls_error(address))?;
    tls_config.alpn_protocols.push(b"h3".to_vec()); // TODO: other alpn as well? Make configurable?
    let quic_client_config = QuicClientConfig::try_from(tls_config)
        .map_err(Hev3Error::map_quic_error(address))?;
    
    Ok(quinn::ClientConfig::new(Arc::new(quic_client_config)))
}

fn create_tls_config(
    ech_config: Option<EchConfigList>
) -> core::result::Result<rustls::ClientConfig, rustls::Error> {
    trace!("start building rustls::ClientConfig");
    let config = config_builder_with_ech_if_available(ech_config)?
        .with_root_certificates(get_native_certs())
        .with_no_client_auth();
    trace!("rustls::ClientConfig built");
    Ok(config)
}

fn config_builder_with_ech_if_available(
    ech_config: Option<EchConfigList>
) -> core::result::Result<ConfigBuilder<rustls::ClientConfig, WantsVerifier>, rustls::Error> {
    let builder = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    );

    if let Some(ech_config) = ech_config {
        let bytes = EchConfigListBytes::from(ech_config.0);
        let supported_suites = rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
        let config = EchConfig::new(bytes, supported_suites)?;
        info!("Using ECH config: {:?}", config);
        builder.with_ech(EchMode::from(config))
    } else {
        builder.with_safe_default_protocol_versions()
    }
}
