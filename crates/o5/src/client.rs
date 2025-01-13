#![allow(unused)]

use crate::{
    common::{colorize, xwing, HmacSha256},
    constants::*,
    framing::{FrameError, Marshall, O5Codec, TryParse, KEY_LENGTH, KEY_MATERIAL_LENGTH},
    handshake::IdentityPublicKey,
    proto::{MaybeTimeout, O5Stream},
    sessions, Error, Result,
};

use bytes::{Buf, BufMut, BytesMut};
use hmac::{Hmac, Mac};
use ptrs::{debug, info, trace, warn};
use rand::prelude::*;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, Instant};

use std::{
    fmt,
    io::{Error as IoError, ErrorKind as IoErrorKind},
    pin::Pin,
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug)]
pub struct ClientBuilder {
    pub node_details: IdentityPublicKey,
    pub statefile_path: Option<String>,
    pub(crate) handshake_timeout: MaybeTimeout,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            node_details: IdentityPublicKey::new([0u8; PUBLIC_KEY_LEN], [0u8; NODE_ID_LENGTH])
                .expect("default identitykey is broken - shouldn't be used anyways"),
            statefile_path: None,
            handshake_timeout: MaybeTimeout::Default_,
        }
    }
}

impl ClientBuilder {
    /// TODO: implement client builder from statefile
    pub fn from_statefile(location: &str) -> Result<Self> {
        todo!("this is not implemented");
        Ok(Self {
            node_details: IdentityPublicKey::new([0u8; PUBLIC_KEY_LEN], [0u8; NODE_ID_LENGTH])?,
            statefile_path: Some(location.into()),
            handshake_timeout: MaybeTimeout::Default_,
        })
    }

    /// TODO: implement client builder from string args
    pub fn from_params(param_strs: Vec<impl AsRef<[u8]>>) -> Result<Self> {
        todo!("this is not implemented");
        Ok(Self {
            node_details: IdentityPublicKey::new([0u8; PUBLIC_KEY_LEN], [0u8; NODE_ID_LENGTH])?,
            statefile_path: None,
            handshake_timeout: MaybeTimeout::Default_,
        })
    }

    pub fn with_node_pubkey(&mut self, pubkey: [u8; PUBLIC_KEY_LEN]) -> Result<&mut Self> {
        self.node_details.ek = xwing::EncapsulationKey::try_from(&pubkey[..])?;
        Ok(self)
    }

    pub(crate) fn with_node(&mut self, pubkey: IdentityPublicKey) -> &mut Self {
        self.node_details = pubkey;
        self
    }

    pub fn with_statefile_path(&mut self, path: &str) -> &mut Self {
        self.statefile_path = Some(path.into());
        self
    }

    pub fn with_node_id(&mut self, id: [u8; NODE_ID_LENGTH]) -> &mut Self {
        self.node_details.id = id.into();
        self
    }

    pub fn with_handshake_timeout(&mut self, d: Duration) -> &mut Self {
        self.handshake_timeout = MaybeTimeout::Length(d);
        self
    }

    pub fn with_handshake_deadline(&mut self, deadline: Instant) -> &mut Self {
        self.handshake_timeout = MaybeTimeout::Fixed(deadline);
        self
    }

    pub fn fail_fast(&mut self) -> &mut Self {
        self.handshake_timeout = MaybeTimeout::Unset;
        self
    }

    pub fn build(&self) -> Client {
        Client {
            station_pubkey: self.node_details.clone(),
            handshake_timeout: self.handshake_timeout.duration(),
        }
    }

    pub fn as_opts(&self) -> String {
        //TODO: String self as command line options
        "".into()
    }
}

impl fmt::Display for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //TODO: string self
        write!(f, "")
    }
}

/// Client implementing the obfs4 protocol.
pub struct Client {
    station_pubkey: IdentityPublicKey,
    handshake_timeout: Option<tokio::time::Duration>,
}

impl Client {
    /// TODO: extract args to create new builder
    pub fn get_args(&mut self, _args: &dyn std::any::Any) {}

    /// On a failed handshake the client will read for the remainder of the
    /// handshake timeout and then close the connection.
    pub async fn wrap<'a, T>(self, mut stream: T) -> Result<O5Stream<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin + 'a,
    {
        let session = sessions::new_client_session(self.station_pubkey);

        let deadline = self.handshake_timeout.map(|d| Instant::now() + d);

        session.handshake(stream, deadline).await
    }

    /// On a failed handshake the client will read for the remainder of the
    /// handshake timeout and then close the connection.
    pub async fn establish<'a, T, E>(
        self,
        mut stream_fut: Pin<ptrs::FutureResult<T, E>>,
    ) -> Result<O5Stream<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin + 'a,
        E: std::error::Error + Send + Sync + 'static,
    {
        let stream = stream_fut.await.map_err(|e| Error::Other(Box::new(e)))?;

        let session = sessions::new_client_session(self.station_pubkey);

        let deadline = self.handshake_timeout.map(|d| Instant::now() + d);

        session.handshake(stream, deadline).await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Result;

    #[test]
    fn parse_params() -> Result<()> {
        let test_args = [["", "", ""]];

        for (i, test_case) in test_args.iter().enumerate() {
            let cb = ClientBuilder::from_params(test_case.to_vec())?;
        }
        Ok(())
    }
}
