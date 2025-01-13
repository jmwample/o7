#![allow(unused)]

use super::*;
use crate::{
    client::ClientBuilder,
    common::{
        colorize, drbg,
        replay_filter::{self, ReplayFilter},
        x25519_elligator2::{PublicKey, StaticSecret},
        HmacSha256,
    },
    constants::*,
    framing::{FrameError, Marshall, Obfs4Codec, TryParse, KEY_LENGTH},
    handshake::{Obfs4NtorPublicKey, Obfs4NtorSecretKey},
    proto::{MaybeTimeout, Obfs4Stream, IAT},
    sessions::Session,
    Error, Result,
};
use ptrs::args::Args;

use std::{borrow::BorrowMut, marker::PhantomData, ops::Deref, str::FromStr, sync::Arc};

use bytes::{Buf, BufMut, Bytes};
use hex::FromHex;
use hmac::{Hmac, Mac};
use ptrs::{debug, info};
use rand::prelude::*;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, Instant};
use tokio_util::codec::Encoder;
use tor_llcrypto::pk::rsa::RsaIdentity;

const STATE_FILENAME: &str = "obfs4_state.json";

pub struct ServerBuilder<T> {
    pub iat_mode: IAT,
    pub statefile_path: Option<String>,
    pub(crate) identity_keys: Obfs4NtorSecretKey,
    pub(crate) handshake_timeout: MaybeTimeout,
    // pub(crate) drbg: Drbg, // TODO: build in DRBG
    _stream_type: PhantomData<T>,
}

impl<T> Default for ServerBuilder<T> {
    fn default() -> Self {
        let identity_keys = Obfs4NtorSecretKey::getrandom();
        Self {
            iat_mode: IAT::Off,
            statefile_path: None,
            identity_keys,
            handshake_timeout: MaybeTimeout::Default_,
            _stream_type: PhantomData,
        }
    }
}

impl<T> ServerBuilder<T> {
    /// 64 byte combined representation of an x25519 public key, private key
    /// combination.
    pub fn node_keys(&mut self, keys: [u8; KEY_LENGTH * 2]) -> &Self {
        let sk: [u8; KEY_LENGTH] = keys[..KEY_LENGTH].try_into().unwrap();
        let pk: [u8; KEY_LENGTH] = keys[KEY_LENGTH..].try_into().unwrap();
        self.identity_keys.sk = sk.into();
        self.identity_keys.pk.pk = (&self.identity_keys.sk).into();
        self
    }

    pub fn statefile_path(&mut self, path: &str) -> &Self {
        self.statefile_path = Some(path.into());
        self
    }

    pub fn node_id(&mut self, id: [u8; NODE_ID_LENGTH]) -> &Self {
        self.identity_keys.pk.id = id.into();
        self
    }

    pub fn iat_mode(&mut self, iat: IAT) -> &Self {
        self.iat_mode = iat;
        self
    }

    pub fn with_handshake_timeout(&mut self, d: Duration) -> &Self {
        self.handshake_timeout = MaybeTimeout::Length(d);
        self
    }

    pub fn with_handshake_deadline(&mut self, deadline: Instant) -> &Self {
        self.handshake_timeout = MaybeTimeout::Fixed(deadline);
        self
    }

    pub fn fail_fast(&mut self) -> &Self {
        self.handshake_timeout = MaybeTimeout::Unset;
        self
    }

    pub fn client_params(&self) -> String {
        let mut params = Args::new();
        params.insert(CERT_ARG.into(), vec![self.identity_keys.pk.to_string()]);
        params.insert(IAT_ARG.into(), vec![self.iat_mode.to_string()]);
        params.encode_smethod_args()
    }

    pub fn build(self) -> Server {
        Server(Arc::new(ServerInner {
            identity_keys: self.identity_keys.clone(),
            iat_mode: self.iat_mode,
            biased: false,
            handshake_timeout: self.handshake_timeout.duration(),

            // metrics: Arc::new(std::sync::Mutex::new(ServerMetrics {})),
            replay_filter: ReplayFilter::new(REPLAY_TTL),
        }))
    }

    pub fn validate_args(args: &Args) -> Result<()> {
        let _ = RequiredServerState::try_from(args)?;

        Ok(())
    }

    pub(crate) fn parse_state(
        statedir: Option<impl AsRef<str>>,
        args: &Args,
    ) -> Result<RequiredServerState> {
        if statedir.is_none() {
            return RequiredServerState::try_from(args);
        }

        // if the provided arguments do not satisfy all required arguments, we
        // attempt to parse the server state from json IFF a statedir path was
        // provided. Otherwise this method just fails.
        let mut required_args = args.clone();
        match RequiredServerState::try_from(args) {
            Ok(state) => Ok(state),
            Err(e) => {
                Self::server_state_from_file(statedir.unwrap(), &mut required_args)?;
                RequiredServerState::try_from(&required_args)
            }
        }
    }

    fn server_state_from_file(statedir: impl AsRef<str>, args: &mut Args) -> Result<()> {
        let mut file_path = String::from(statedir.as_ref());
        file_path.push_str(STATE_FILENAME);

        let state_str = std::fs::read(file_path)?;

        Self::server_state_from_json(&state_str[..], args)
    }

    fn server_state_from_json(state_rdr: impl std::io::Read, args: &mut Args) -> Result<()> {
        let state: JsonServerState =
            serde_json::from_reader(state_rdr).map_err(|e| Error::Other(Box::new(e)))?;

        state.extend_args(args);
        Ok(())
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct JsonServerState {
    #[serde(rename = "node-id")]
    node_id: Option<String>,
    #[serde(rename = "private-key")]
    private_key: Option<String>,
    #[serde(rename = "public-key")]
    public_key: Option<String>,
    #[serde(rename = "drbg-seed")]
    drbg_seed: Option<String>,
    #[serde(rename = "iat-mode")]
    iat_mode: Option<String>,
}

impl JsonServerState {
    fn extend_args(self, args: &mut Args) {
        if let Some(id) = self.node_id {
            args.add(NODE_ID_ARG, &id);
        }
        if let Some(sk) = self.private_key {
            args.add(PRIVATE_KEY_ARG, &sk);
        }
        if let Some(pubkey) = self.public_key {
            args.add(PUBLIC_KEY_ARG, &pubkey);
        }
        if let Some(seed) = self.drbg_seed {
            args.add(SEED_ARG, &seed);
        }
        if let Some(mode) = self.iat_mode {
            args.add(IAT_ARG, &mode);
        }
    }
}

pub(crate) struct RequiredServerState {
    pub(crate) private_key: Obfs4NtorSecretKey,
    pub(crate) drbg_seed: drbg::Drbg,
    pub(crate) iat_mode: IAT,
}

impl TryFrom<&Args> for RequiredServerState {
    type Error = Error;
    fn try_from(value: &Args) -> std::prelude::v1::Result<Self, Self::Error> {
        let privkey_str = value
            .retrieve(PRIVATE_KEY_ARG)
            .ok_or("missing argument {PRIVATE_KEY_ARG}")?;
        let sk = <[u8; KEY_LENGTH]>::from_hex(privkey_str)?;

        let drbg_seed_str = value
            .retrieve(SEED_ARG)
            .ok_or("missing argument {SEED_ARG}")?;
        let drbg_seed = drbg::Seed::from_hex(drbg_seed_str)?;

        let node_id_str = value
            .retrieve(NODE_ID_ARG)
            .ok_or("missing argument {NODE_ID_ARG}")?;
        let node_id = <[u8; NODE_ID_LENGTH]>::from_hex(node_id_str)?;

        let iat_mode = match value.retrieve(IAT_ARG) {
            Some(s) => IAT::from_str(&s)?,
            None => IAT::default(),
        };

        let secret_key = StaticSecret::from(sk);
        let private_key = Obfs4NtorSecretKey::new(secret_key, RsaIdentity::from(node_id));

        Ok(RequiredServerState {
            private_key,
            drbg_seed: drbg::Drbg::new(Some(drbg_seed))?,
            iat_mode,
        })
    }
}

#[derive(Clone)]
pub struct Server(Arc<ServerInner>);

pub struct ServerInner {
    pub(crate) handshake_timeout: Option<tokio::time::Duration>,
    pub(crate) iat_mode: IAT,
    pub(crate) biased: bool,
    pub(crate) identity_keys: Obfs4NtorSecretKey,

    pub(crate) replay_filter: ReplayFilter,
    // pub(crate) metrics: Metrics,
}

impl Deref for Server {
    type Target = ServerInner;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl Server {
    pub fn new(sec: [u8; KEY_LENGTH], id: [u8; NODE_ID_LENGTH]) -> Self {
        let sk = StaticSecret::from(sec);
        let pk = Obfs4NtorPublicKey {
            pk: PublicKey::from(&sk),
            id: id.into(),
        };

        let identity_keys = Obfs4NtorSecretKey { pk, sk };

        Self::new_from_key(identity_keys)
    }

    pub(crate) fn new_from_key(identity_keys: Obfs4NtorSecretKey) -> Self {
        Self(Arc::new(ServerInner {
            handshake_timeout: Some(SERVER_HANDSHAKE_TIMEOUT),
            identity_keys,
            iat_mode: IAT::Off,
            biased: false,

            // metrics: Arc::new(std::sync::Mutex::new(ServerMetrics {})),
            replay_filter: ReplayFilter::new(REPLAY_TTL),
        }))
    }

    pub fn new_from_random<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let mut id = [0_u8; 20];
        // Random bytes will work for testing, but aren't necessarily actually a valid id.
        rng.fill_bytes(&mut id);

        // Generated identity secret key does not need to be elligator2 representable
        // so we can use the regular dalek_x25519 key generation.
        let sk = StaticSecret::random_from_rng(rng);

        let pk = Obfs4NtorPublicKey {
            pk: PublicKey::from(&sk),
            id: id.into(),
        };

        let identity_keys = Obfs4NtorSecretKey { pk, sk };

        Self::new_from_key(identity_keys)
    }

    pub fn getrandom() -> Self {
        let identity_keys = Obfs4NtorSecretKey::getrandom();
        Self::new_from_key(identity_keys)
    }

    pub async fn wrap<T>(self, stream: T) -> Result<Obfs4Stream<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session = self.new_server_session()?;
        let deadline = self.handshake_timeout.map(|d| Instant::now() + d);

        session.handshake(&self, stream, deadline).await
    }

    // pub fn set_iat_mode(&mut self, mode: IAT) -> &Self {
    //     self.iat_mode = mode;
    //     self
    // }

    pub fn set_args(&mut self, args: &dyn std::any::Any) -> Result<&Self> {
        Ok(self)
    }

    pub fn new_from_statefile() -> Result<Self> {
        Err(Error::NotImplemented)
    }

    pub fn write_statefile(f: std::fs::File) -> Result<()> {
        Err(Error::NotImplemented)
    }

    pub fn client_params(&self) -> ClientBuilder {
        ClientBuilder {
            station_pubkey: *self.identity_keys.pk.pk.as_bytes(),
            station_id: self.identity_keys.pk.id.as_bytes().try_into().unwrap(),
            iat_mode: self.iat_mode,
            statefile_path: None,
            handshake_timeout: MaybeTimeout::Default_,
        }
    }

    pub(crate) fn new_server_session(
        &self,
    ) -> Result<sessions::ServerSession<sessions::Initialized>> {
        let mut session_id = [0u8; SESSION_ID_LEN];
        rand::thread_rng().fill_bytes(&mut session_id);
        Ok(sessions::ServerSession {
            // fixed by server
            identity_keys: self.identity_keys.clone(),
            biased: self.biased,

            // generated per session
            session_id,
            len_seed: drbg::Seed::new().unwrap(),
            iat_seed: drbg::Seed::new().unwrap(),

            _state: sessions::Initialized {},
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::dev;

    use super::*;

    use ptrs::trace;
    use tokio::net::TcpStream;

    #[test]
    fn parse_json_state() -> Result<()> {
        crate::test_utils::init_subscriber();

        let mut args = Args::new();
        let test_state = format!(
            r#"{{"{NODE_ID_ARG}": "00112233445566778899", "{PRIVATE_KEY_ARG}":"0123456789abcdeffedcba9876543210", "{IAT_ARG}": "0", "{SEED_ARG}": "abcdefabcdefabcdefabcdef"}}"#
        );
        ServerBuilder::<TcpStream>::server_state_from_json(test_state.as_bytes(), &mut args)?;
        debug!("{:?}\n{}", args.encode_smethod_args(), test_state);

        Ok(())
    }
}
