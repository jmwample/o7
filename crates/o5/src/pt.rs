use crate::{
    common::xwing, constants::*, handshake::IdentityPublicKey, proto::O5Stream, Error,
    TRANSPORT_NAME,
};
use ptrs::{args::Args, FutureResult as F};

use std::{
    marker::PhantomData,
    net::{SocketAddrV4, SocketAddrV6},
    pin::Pin,
    str::FromStr,
    time::Duration,
};

use hex::FromHex;
use ptrs::trace;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

pub type O5PT = Transport<TcpStream>;

#[derive(Debug, Default)]
pub struct Transport<T> {
    _p: PhantomData<T>,
}
impl<T> Transport<T> {
    pub const NAME: &'static str = TRANSPORT_NAME;
}

impl<T> ptrs::PluggableTransport<T> for Transport<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type ClientBuilder = crate::ClientBuilder;
    type ServerBuilder = crate::ServerBuilder<T>;

    fn name() -> String {
        TRANSPORT_NAME.into()
    }

    fn client_builder() -> <Self as ptrs::PluggableTransport<T>>::ClientBuilder {
        crate::ClientBuilder::default()
    }

    fn server_builder() -> <Self as ptrs::PluggableTransport<T>>::ServerBuilder {
        crate::ServerBuilder::default()
    }
}

impl<T> ptrs::ServerBuilder<T> for crate::ServerBuilder<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type ServerPT = crate::Server;
    type Error = Error;
    type Transport = Transport<T>;

    fn build(self) -> Self::ServerPT {
        crate::ServerBuilder::build(self)
    }

    fn method_name() -> String {
        TRANSPORT_NAME.into()
    }

    fn options(&mut self, opts: &Args) -> Result<&mut Self, Self::Error> {
        // TODO: pass on opts

        let state = Self::parse_state(None::<&str>, opts)?;
        self.identity_keys = state.private_key;
        // self.drbg = state.drbg_seed; // TODO apply seed from args to server

        trace!(
            "node_pubkey: {}, node_id: {}",
            hex::encode(self.identity_keys.pk.ek.as_bytes()),
            hex::encode(self.identity_keys.pk.id.as_bytes()),
        );
        Ok(self)
    }

    fn get_client_params(&self) -> String {
        self.client_params()
    }

    fn statefile_location(&mut self, _path: &str) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    fn timeout(&mut self, _timeout: Option<Duration>) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    fn v4_bind_addr(&mut self, _addr: SocketAddrV4) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    fn v6_bind_addr(&mut self, _addr: SocketAddrV6) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }
}

impl<T> ptrs::ClientBuilder<T> for crate::ClientBuilder
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type ClientPT = crate::Client;
    type Error = Error;
    type Transport = Transport<T>;

    fn method_name() -> String {
        TRANSPORT_NAME.into()
    }

    /// Builds a new PtCommonParameters.
    ///
    /// **Errors**
    /// If a required field has not been initialized.
    fn build(&self) -> Self::ClientPT {
        crate::ClientBuilder::build(self)
    }

    /// Pluggable transport attempts to parse and validate options from a string,
    /// typically using ['parse_smethod_args'].
    fn options(&mut self, opts: &Args) -> Result<&mut Self, Self::Error> {
        let server_materials = match opts.retrieve(CERT_ARG) {
            Some(cert_strs) => {
                // The "new" (version >= 0.0.3) bridge lines use a unified "cert" argument
                // for the Node ID and Public Key.
                if cert_strs.is_empty() {
                    return Err(format!("missing argument '{NODE_ID_ARG}'").into());
                }
                trace!("cert string: {}", &cert_strs);
                IdentityPublicKey::from_str(&cert_strs)?
            }
            None => {
                // The "old" style (version <= 0.0.2) bridge lines use separate Node ID
                // and Public Key arguments in Base16 encoding and are a UX disaster.
                let node_id_strs = opts
                    .retrieve(NODE_ID_ARG)
                    .ok_or(format!("missing argument '{NODE_ID_ARG}'"))?;
                let id = <[u8; NODE_ID_LENGTH]>::from_hex(node_id_strs)
                    .map_err(|e| format!("malformed node id: {e}"))?;

                let public_key_strs = opts
                    .retrieve(PUBLIC_KEY_ARG)
                    .ok_or(format!("missing argument '{PUBLIC_KEY_ARG}'"))?;

                IdentityPublicKey::from_str(&public_key_strs)
                    .map_err(|e| format!("malformed public key: {e}"))?
            }
        };

        self.with_node(server_materials);
        trace!("node details: {:?}", &self.node_details,);

        Ok(self)
    }

    /// A path where the launched PT can store state.
    fn statefile_location(&mut self, _path: &str) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    /// The maximum time we should wait for a pluggable transport binary to
    /// report successful initialization. If `None`, a default value is used.
    fn timeout(&mut self, _timeout: Option<Duration>) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    /// An IPv4 address to bind outgoing connections to (if specified).
    ///
    /// Leaving this out will mean the PT uses a sane default.
    fn v4_bind_addr(&mut self, _addr: SocketAddrV4) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    /// An IPv6 address to bind outgoing connections to (if specified).
    ///
    /// Leaving this out will mean the PT uses a sane default.
    fn v6_bind_addr(&mut self, _addr: SocketAddrV6) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }
}

/// Example wrapping transport that just passes the incoming connection future through
/// unmodified as a proof of concept.
impl<InRW, InErr> ptrs::ClientTransport<InRW, InErr> for crate::Client
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    InErr: std::error::Error + Send + Sync + 'static,
{
    type OutRW = O5Stream<InRW>;
    type OutErr = Error;
    type Builder = crate::ClientBuilder;

    fn establish(self, input: Pin<F<InRW, InErr>>) -> Pin<F<Self::OutRW, Self::OutErr>> {
        Box::pin(crate::Client::establish(self, input))
    }

    fn wrap(self, io: InRW) -> Pin<F<Self::OutRW, Self::OutErr>> {
        Box::pin(crate::Client::wrap(self, io))
    }

    fn method_name() -> String {
        TRANSPORT_NAME.into()
    }
}

impl<InRW> ptrs::ServerTransport<InRW> for crate::Server
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type OutRW = O5Stream<InRW>;
    type OutErr = Error;
    type Builder = crate::ServerBuilder<InRW>;

    /// Use something that can be accessed reference (Arc, Rc, etc.)
    fn reveal(self, io: InRW) -> Pin<F<Self::OutRW, Self::OutErr>> {
        Box::pin(crate::Server::wrap(self, io))
    }

    fn method_name() -> String {
        TRANSPORT_NAME.into()
    }

    fn get_client_params(&self) -> String {
        self.client_params().as_opts()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_name() {
        let pt_name = <O5PT as ptrs::PluggableTransport<TcpStream>>::name();
        assert_eq!(pt_name, O5PT::NAME);

        let cb_name = <crate::ClientBuilder as ptrs::ClientBuilder<TcpStream>>::method_name();
        assert_eq!(cb_name, O5PT::NAME);

        let sb_name =
            <crate::ServerBuilder<TcpStream> as ptrs::ServerBuilder<TcpStream>>::method_name();
        assert_eq!(sb_name, O5PT::NAME);

        let ct_name =
            <crate::Client as ptrs::ClientTransport<TcpStream, crate::Error>>::method_name();
        assert_eq!(ct_name, O5PT::NAME);

        let st_name = <crate::Server as ptrs::ServerTransport<TcpStream>>::method_name();
        assert_eq!(st_name, O5PT::NAME);
    }
}
