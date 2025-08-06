use std::error::Error;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Hev3Error {
    #[error("Name resolution error: {0}")]
    ResolveError(#[from] hickory_resolver::ResolveError),
    
    #[error("TCP error: {0}")]
    TcpError(Box<dyn Error + Send + Sync>),
    
    #[error("TLS error: {0}")]
    TlsError(Box<dyn Error + Send + Sync>),
    
    #[error("QUIC error: {0}")]
    QuicError(Box<dyn Error + Send + Sync>),
    
    #[error("No addresses found")]
    NoAddressesFound,
    
    #[error("No route available")]
    NoRouteAvailable,
    
    #[error("Timeout while waiting for connection")]
    Timeout,
}

// Helper implementations for automatic error conversion
impl From<rustls::Error> for Hev3Error {
    fn from(err: rustls::Error) -> Self {
        Hev3Error::TlsError(Box::new(err))
    }
}

impl From<quinn::ConnectError> for Hev3Error {
    fn from(err: quinn::ConnectError) -> Self {
        Hev3Error::QuicError(Box::new(err))
    }
}

impl From<quinn::ConnectionError> for Hev3Error {
    fn from(err: quinn::ConnectionError) -> Self {
        Hev3Error::QuicError(Box::new(err))
    }
}

impl Hev3Error {
    pub fn tcp_error<E: Error + Send + Sync + 'static>(err: E) -> Self {
        Hev3Error::TcpError(Box::new(err))
    }

    pub fn tls_error<E: Error + Send + Sync + 'static>(err: E) -> Self {
        Hev3Error::TlsError(Box::new(err))
    }
    
    pub fn quic_error<E: Error + Send + Sync + 'static>(err: E) -> Self {
        Hev3Error::QuicError(Box::new(err))
    }
}
