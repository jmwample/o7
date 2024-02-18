#![allow(unused)]

use crate::{
    common::{colorize, HmacSha256},
    obfs4::{
        constants::*,
        sessions,
        framing::{FrameError, Marshall, Obfs4Codec, TryParse, KEY_LENGTH, KEY_MATERIAL_LENGTH},
        handshake::Obfs4NtorPublicKey,
        proto::{MaybeTimeout, Obfs4Stream, IAT},
    },
    stream::Stream,
    Error, Result,
};

use bytes::{Buf, BufMut, BytesMut};
use hmac::{Hmac, Mac};
use rand::prelude::*;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

use std::{
    fmt,
    io::{Error as IoError, ErrorKind as IoErrorKind},
    sync::{Arc, Mutex},
};

pub struct ClientBuilder {
    pub iat_mode: IAT,
    pub station_pubkey: Obfs4NtorPublicKey,
    pub statefile_location: Option<String>,
    pub(crate) handshake_timeout: MaybeTimeout,
}

impl ClientBuilder {
    /// TODO: implement client builder from statefile
    pub fn from_statefile(location: &str) -> Result<Self> {
        let station_pubkey = Obfs4NtorPublicKey {
            pk: [0_u8; KEY_LENGTH].into(),
            id: [0_u8; NODE_ID_LENGTH].into(),
        };

        Ok(Self {
            iat_mode: IAT::Off,
            station_pubkey,
            statefile_location: Some(location.into()),
            handshake_timeout: MaybeTimeout::Default_,
        })
    }

    /// TODO: implement client builder from string args
    pub fn from_params(param_strs: Vec<impl AsRef<[u8]>>) -> Result<Self> {
        let station_pubkey = Obfs4NtorPublicKey {
            pk: [0_u8; KEY_LENGTH].into(),
            id: [0_u8; NODE_ID_LENGTH].into(),
        };

        Ok(Self {
            iat_mode: IAT::Off,
            station_pubkey,
            statefile_location: None,
            handshake_timeout: MaybeTimeout::Default_,
        })
    }

    pub fn with_node_pubkey(mut self, pubkey: [u8; KEY_LENGTH]) -> Self {
        self.station_pubkey.pk = pubkey.into();
        self
    }

    pub fn with_statefile_location(mut self, path: &str) -> Self {
        self.statefile_location = Some(path.into());
        self
    }

    pub fn with_node_id(mut self, id: [u8; NODE_ID_LENGTH]) -> Self {
        self.station_pubkey.id = id.into();
        self
    }

    pub fn with_iat_mode(mut self, iat: IAT) -> Self {
        self.iat_mode = iat;
        self
    }

    pub fn with_handshake_timeout(mut self, d: Duration) -> Self {
        self.handshake_timeout = MaybeTimeout::Length(d);
        self
    }

    pub fn with_handshake_deadline(mut self, deadline: Instant) -> Self {
        self.handshake_timeout = MaybeTimeout::Fixed(deadline);
        self
    }

    pub fn fail_fast(mut self) -> Self {
        self.handshake_timeout = MaybeTimeout::Unset;
        self
    }

    pub fn build(self) -> Client {
        Client {
            iat_mode: self.iat_mode,
            station_pubkey: self.station_pubkey,
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
    iat_mode: IAT,
    station_pubkey: Obfs4NtorPublicKey,
    handshake_timeout: Option<tokio::time::Duration>,
}

impl Client {
    /// TODO: extract args to create new builder
    pub fn get_args(&mut self, _args: &dyn std::any::Any) {}

    /// On a failed handshake the client will read for the remainder of the
    /// handshake timeout and then close the connection.
    pub async fn wrap<'a, T>(&self, mut stream: T) -> Result<Obfs4Stream<'a, T>>
    where
        T: AsyncRead + AsyncWrite + Unpin + 'a,
    {
        let session = sessions::new_client_session(self.station_pubkey, self.iat_mode);

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
