use std::error::Error;
use thiserror::Error;
use std::net::IpAddr;

#[derive(Debug, Error)]
pub enum Hev3Error {
    #[error("Name resolution error: {0}")]
    ResolveError(#[from] hickory_resolver::ResolveError),
    
    #[error("TCP error for {0}: {1}")]
    TcpError(IpAddr, Box<dyn Error + Send + Sync>),
    
    #[error("TLS error for {0}: {1}")]
    TlsError(IpAddr, Box<dyn Error + Send + Sync>),
    
    #[error("QUIC error for {0}: {1}")]
    QuicError(IpAddr, Box<dyn Error + Send + Sync>),
    
    #[error("No addresses found")]
    NoAddressesFound,
    
    #[error("No route available")]
    NoRouteAvailable,
    
    #[error("Timeout while waiting for connection")]
    Timeout,
}

impl Hev3Error {
    pub fn map_tcp_error<E>(address: IpAddr) -> impl FnOnce(E) -> Hev3Error
    where E: Error + Send + Sync + 'static {
        move |err| Hev3Error::TcpError(address, Box::new(err))
    }

    pub fn map_tls_error<E>(address: IpAddr) -> impl FnOnce(E) -> Hev3Error 
    where E: Error + Send + Sync + 'static {
        move |err| Hev3Error::TlsError(address, Box::new(err))
    }
    
    pub fn map_quic_error<E>(address: IpAddr) -> impl FnOnce(E) -> Hev3Error 
    where E: Error + Send + Sync + 'static {
        move |err| Hev3Error::QuicError(address, Box::new(err))
    }
}
