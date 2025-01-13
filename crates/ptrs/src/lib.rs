#![doc = include_str!("../README.md")]

use std::{
    net::{SocketAddrV4, SocketAddrV6},
    pin::Pin,
    time::{Duration, Instant},
};

use futures::Future; // , Sink, TryStream};
use tokio::io::{AsyncRead, AsyncWrite};

mod error;
pub use error::Error;
#[macro_use]
pub mod args;
mod helpers;
pub use helpers::*;
mod log;
pub mod orport;

pub trait PluggableTransport<InRW>
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type ClientBuilder: ClientBuilder<InRW>;
    type ServerBuilder: ServerBuilder<InRW>;

    /// Returns a string identifier for this transport
    fn name() -> String;

    fn client_builder() -> <Self as PluggableTransport<InRW>>::ClientBuilder;

    fn server_builder() -> <Self as PluggableTransport<InRW>>::ServerBuilder;
}

// ================================================================ //
//                            Client                                //
// ================================================================ //

/// Client Transport Builder
// Struct builder, passed by type and then built from default for each client
// with params baked in as builder pattern.
pub trait ClientBuilder<InRW>: Default + Clone
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type Error: std::error::Error + Send + Sync;
    type ClientPT: ClientTransport<InRW, Self::Error>;
    type Transport;

    /// Returns a string identifier for this transport
    fn method_name() -> String;

    /// Builds a new PtCommonParameters.
    ///
    /// **Errors**
    /// If a required field has not been initialized.
    fn build(&self) -> Self::ClientPT;

    /// Pluggable transport attempts to parse and validate options from a string,
    /// typically using ['parse_smethod_args'].
    fn options(&mut self, opts: &args::Args) -> Result<&mut Self, Self::Error>;

    /// A path where the launched PT can store state.
    fn statefile_location(&mut self, path: &str) -> Result<&mut Self, Self::Error>;

    /// The maximum time we should wait for a pluggable transport binary to
    /// report successful initialization. If `None`, a default value is used.
    fn timeout(&mut self, timeout: Option<Duration>) -> Result<&mut Self, Self::Error>;

    /// An IPv4 address to bind outgoing connections to (if specified).
    ///
    /// Leaving this out will mean the PT uses a sane default.
    fn v4_bind_addr(&mut self, addr: SocketAddrV4) -> Result<&mut Self, Self::Error>;

    /// An IPv6 address to bind outgoing connections to (if specified).
    ///
    /// Leaving this out will mean the PT uses a sane default.
    fn v6_bind_addr(&mut self, addr: SocketAddrV6) -> Result<&mut Self, Self::Error>;
}

/// Client Transport
pub trait ClientTransport<InRW, InErr>
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type OutRW: AsyncRead + AsyncWrite + Send + Unpin;
    type OutErr: std::error::Error + Send + Sync;
    type Builder: ClientBuilder<InRW>;

    /// Create a pluggable transport connection given a future that will return
    /// a Read/Write object that can be used as the underlying socket for the
    /// connection.
    fn establish(self, input: Pin<F<InRW, InErr>>) -> Pin<F<Self::OutRW, Self::OutErr>>;

    /// Create a connection for the pluggable transport client using the provided
    /// (pre-existing/pre-connected) Read/Write object as the underlying socket.
    fn wrap(self, io: InRW) -> Pin<F<Self::OutRW, Self::OutErr>>;

    /// Returns a string identifier for this transport
    fn method_name() -> String;
}

// ================================================================ //
//                            Server                                //
// ================================================================ //

/// Server Transport
// try using objects so we can accept and then handshake (proxy equivalent of
// accept) as separate steps by the transport user.
pub trait ServerTransport<InRW>
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type OutRW: AsyncRead + AsyncWrite + Send + Unpin;
    type OutErr: std::error::Error + Send + Sync;
    type Builder: ServerBuilder<InRW>;

    /// Create/accept a connection for the pluggable transport client using the
    /// provided (pre-existing/pre-connected) Read/Write object as the
    /// underlying socket.
    ///
    /// Uses `self` instead of `&self` to encourage/force use of reference
    /// counted objects (Arc, Rc) for server implementations where the server
    /// needs internal mutability across multiple threads concurrently.
    fn reveal(self, io: InRW) -> Pin<F<Self::OutRW, Self::OutErr>>;

    /// Returns a string identifier for this transport
    fn method_name() -> String;

    /// Returns a string or parameters that can be used by a ['ClientBuilder']
    /// in the `options(...)` function to properly establish a connection with
    /// this server based on the configuration of the server when this method
    /// is called.
    fn get_client_params(&self) -> String;
}

/// Server Transport builder interface
pub trait ServerBuilder<InRW>: Default
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type ServerPT: ServerTransport<InRW>;
    type Error: std::error::Error;
    type Transport;

    /// Returns a string identifier for this transport
    fn method_name() -> String;

    /// Builds a new PtCommonParameters.
    ///
    /// **Errors**
    /// If a required field has not been initialized.
    fn build(self) -> Self::ServerPT;

    /// Pluggable transport attempts to parse and validate options from a string,
    /// typically using ['parse_smethod_args'].
    fn options(&mut self, opts: &args::Args) -> Result<&mut Self, Self::Error>;

    /// Returns a string or parameters that can be used by a ['ClientBuilder']
    /// in the `options(...)` function to properly establish a connection with
    /// this server based on the configuration of the server when this method
    /// is called.
    fn get_client_params(&self) -> String;

    /// A path where the launched PT can store state.
    fn statefile_location(&mut self, path: &str) -> Result<&mut Self, Self::Error>;

    /// The maximum time we should wait for a pluggable transport binary to
    /// report successful initialization. If `None`, a default value is used.
    fn timeout(&mut self, timeout: Option<Duration>) -> Result<&mut Self, Self::Error>;

    /// An IPv4 address to bind outgoing connections to (if specified).
    ///
    /// Leaving this out will mean the PT uses a sane default.
    fn v4_bind_addr(&mut self, addr: SocketAddrV4) -> Result<&mut Self, Self::Error>;

    /// An IPv6 address to bind outgoing connections to (if specified).
    ///
    /// Leaving this out will mean the PT uses a sane default.
    fn v6_bind_addr(&mut self, addr: SocketAddrV6) -> Result<&mut Self, Self::Error>;
}

// ================================================================ //
//                        Connections                               //
// ================================================================ //

/// Creator1 defines a stream creator that could be applied to either the input
/// stream feature or the resulting stream future making them composable.
pub trait Conn {
    type OutRW;
    type OutErr;
    type Future: Future<Output = Result<Self::OutRW, Self::OutErr>>;

    fn new() -> Self::Future;
}

/// In concept this trait provides extended functionality that can be appled to
/// the client / server traits for creating connections / pluggable transports.
/// this is still in a TODO state.
pub trait ConnectExt: Conn {
    fn connect_with_deadline(
        &mut self,
        deadline: Instant,
    ) -> Result<Self::Future, tokio::time::error::Elapsed>;
    fn connect_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Self::Future, tokio::time::error::Elapsed>;
}

impl Conn for tokio::net::TcpStream {
    type OutRW = Self;
    type OutErr = std::io::Error;
    type Future = Pin<F<Self::OutRW, Self::OutErr>>;

    fn new() -> Self::Future {
        let f = tokio::net::TcpStream::connect("127.0.0.1:9000");
        Box::pin(f)
    }
}

impl Conn for tokio::net::UdpSocket {
    type OutErr = std::io::Error;
    type OutRW = tokio::net::UdpSocket;
    type Future = Pin<F<Self::OutRW, Self::OutErr>>;

    fn new() -> Self::Future {
        let f = tokio::net::UdpSocket::bind("127.0.0.1:9000");
        Box::pin(f)
    }
}

/// Future containing a generic result. We use this for functions that take
/// and/or return futures that will produce Read/Write tunnels once awaited.
pub type FutureResult<T, E> = Box<dyn Future<Output = Result<T, E>> + Send>;

/// Future containing a generic result, shorthand for ['FutureResult']. We use
/// this for functions that take and/or return futures that will produce
/// Read/Write tunnels once awaited.
pub(crate) type F<T, E> = FutureResult<T, E>;

pub type TcpStreamFut = Pin<FutureResult<tokio::net::TcpStream, std::io::Error>>;

pub type UdpSocketFut = Pin<FutureResult<tokio::net::UdpSocket, std::io::Error>>;

#[cfg(test)]
mod passthrough;
