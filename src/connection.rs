use crate::hev3_client::{Hev3Error, Result};
use log::debug;
use quinn::{crypto::rustls::QuicClientConfig, Endpoint};
use rustls::RootCertStore;
use std::net::IpAddr;
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

pub async fn connect_tcp_tls(address: IpAddr) -> Result<Hev3Stream> {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let domain = address.into();
    debug!("Starting connection to {}", address); // TODO measure time
    let stream = TcpStream::connect((address, 443)).await.map_err(Hev3Error::tcp_error)?;
    debug!("Connected to {}", address);
    let tls_stream = connector.connect(domain, stream).await.map_err(Hev3Error::tls_error)?;
    debug!("TLS stream established");

    Ok(Hev3Stream::Tls(tls_stream))
} 

pub async fn connect_quic(address: IpAddr, server_name: &str) -> Result<Hev3Stream> {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let quic_client_config = Arc::new(
        QuicClientConfig::try_from(client_crypto).map_err(Hev3Error::quic_error)?
    );
    let client_config = quinn::ClientConfig::new(quic_client_config);

    let socket_addr = SocketAddr::new(address, 443);

    let mut endpoint = Endpoint::client(socket_addr).map_err(Hev3Error::quic_error)?;
    endpoint.set_default_client_config(client_config);
        
    debug!("Starting QUIC connection to {}", address); // TODO measure time
    let connection = endpoint.connect(socket_addr, server_name)?.await?;
    debug!("QUIC connection established to {}", address);
    
    Ok(Hev3Stream::Quic(connection))
}
