#![allow(unused)] // TODO: Remove this

use crate::{
    client::ClientBuilder,
    common::{
        colorize, drbg,
        replay_filter::{self, ReplayFilter},
        HmacSha256,
    },
    constants::*,
    framing::{FrameError, Marshall, O5Codec, TryParse, KEY_LENGTH},
    handshake::{IdentityPublicKey, IdentitySecretKey},
    proto::{MaybeTimeout, O5Stream},
    sessions::{Initialized, ServerSession, Session},
    traits::{DigestSizes, FramingSizes, OKemCore},
    transport_name, Digest, Error, Result,
};

use std::{
    borrow::BorrowMut, marker::PhantomData, ops::Deref, str::FromStr, string::ToString, sync::Arc,
};

use bytes::{Buf, BufMut, Bytes};
use hex::FromHex;
use hmac::{Hmac, Mac};
use ptrs::{args::Args, debug, info};
use rand::prelude::*;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, Instant};
use tokio_util::codec::Encoder;
use tor_cell::relaycell::extend::NtorV3Extension;

const STATE_FILENAME: &str = "o5_state.json";

pub struct ServerBuilder<T, K: OKemCore, D: Digest> {
    pub statefile_path: Option<String>,
    pub(crate) identity_keys: IdentitySecretKey<K>,
    pub(crate) handshake_timeout: MaybeTimeout,
    // pub(crate) drbg: Drbg, // TODO: build in DRBG
    _stream_type: PhantomData<T>,
    _digest_type: PhantomData<D>,
}

impl<T, K: OKemCore, D: Digest> Default for ServerBuilder<T, K, D> {
    fn default() -> Self {
        let identity_keys = IdentitySecretKey::<K>::random_from_rng(&mut rand::thread_rng());
        Self {
            statefile_path: None,
            identity_keys,
            handshake_timeout: MaybeTimeout::Default_,
            _stream_type: PhantomData,
            _digest_type: PhantomData,
        }
    }
}

impl<T, K: OKemCore, D: Digest> ServerBuilder<T, K, D> {
    /// 64 byte combined representation of an x25519 public key, private key
    /// combination.
    pub fn node_keys(&mut self, keys: impl AsRef<[u8]>) -> Result<&Self> {
        let sk = IdentitySecretKey::<K>::try_from(keys.as_ref())?;
        self.identity_keys = sk;
        Ok(self)
    }

    pub fn statefile_path(&mut self, path: &str) -> &Self {
        self.statefile_path = Some(path.into());
        self
    }

    pub fn node_id(&mut self, id: [u8; NODE_ID_LENGTH]) -> &Self {
        self.identity_keys.pk.id = id.into();
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
        params.encode_smethod_args()
    }

    pub fn build(self) -> Server<K, D> {
        Server::<K, D>(Arc::new(ServerCore::<K, D> {
            identity_keys: self.identity_keys,
            biased: false,
            handshake_timeout: self.handshake_timeout.duration(),

            // metrics: Arc::new(std::sync::Mutex::new(ServerMetrics {})),
            replay_filter: ReplayFilter::new(REPLAY_TTL),
            _digest_type: PhantomData::<D>,
        }))
    }

    pub fn validate_args(args: &Args) -> Result<()> {
        let _ = RequiredServerState::<K>::try_from(args)?;

        Ok(())
    }

    pub(crate) fn parse_state(
        statedir: Option<impl AsRef<str>>,
        args: &Args,
    ) -> Result<RequiredServerState<K>> {
        if statedir.is_none() {
            return RequiredServerState::<K>::try_from(args);
        }

        // if the provided arguments do not satisfy all required arguments, we
        // attempt to parse the server state from json IFF a statedir path was
        // provided. Otherwise this method just fails.
        let mut required_args = args.clone();
        match RequiredServerState::<K>::try_from(args) {
            Ok(state) => Ok(state),
            Err(e) => {
                Self::server_state_from_file(statedir.unwrap(), &mut required_args)?;
                RequiredServerState::<K>::try_from(&required_args)
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
    }
}

pub(crate) struct RequiredServerState<K: OKemCore> {
    pub(crate) private_key: IdentitySecretKey<K>,
    pub(crate) drbg_seed: drbg::Drbg,
}

impl<K: OKemCore> TryFrom<&Args> for RequiredServerState<K> {
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

        let private_key = IdentitySecretKey::<K>::try_from_bytes(sk)?;

        Ok(RequiredServerState::<K> {
            private_key,
            drbg_seed: drbg::Drbg::new(Some(drbg_seed))?,
        })
    }
}

#[derive(Clone)]
pub struct Server<K: OKemCore, D: Digest>(Arc<ServerCore<K, D>>);

pub struct ServerCore<K: OKemCore, D: Digest> {
    pub(crate) handshake_timeout: Option<tokio::time::Duration>,
    pub(crate) biased: bool,
    pub(crate) identity_keys: IdentitySecretKey<K>,

    pub(crate) replay_filter: ReplayFilter,

    _digest_type: PhantomData<D>,
}

impl<K: OKemCore, D: Digest> Deref for Server<K, D> {
    type Target = ServerCore<K, D>;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<K: OKemCore, D: Digest> Server<K, D> {
    pub(crate) const CT_SIZE: usize = K::CT_SIZE;
    pub(crate) const EK_SIZE: usize = K::EK_SIZE;
    pub(crate) const AUTH_SIZE: usize = D::AUTH_SIZE;
    pub const SERVER_MIN_HANDSHAKE_LENGTH: usize =
        K::CT_SIZE + D::AUTH_SIZE + D::MARK_SIZE + D::MAC_SIZE;
    pub const SERVER_MAX_PAD_LENGTH: usize = MAX_PACKET_LENGTH - Self::SERVER_MIN_HANDSHAKE_LENGTH;

    pub fn new(identity: IdentitySecretKey<K>) -> Self {
        Self::new_from_key(identity)
    }

    pub(crate) fn new_from_key(identity_keys: IdentitySecretKey<K>) -> Self {
        Self(Arc::new(ServerCore {
            handshake_timeout: Some(SERVER_HANDSHAKE_TIMEOUT),
            identity_keys,
            biased: false,

            // metrics: Arc::new(std::sync::Mutex::new(ServerMetrics {})),
            replay_filter: ReplayFilter::new(REPLAY_TTL),
            _digest_type: PhantomData::<D>,
        }))
    }

    pub fn new_from_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut id = [0_u8; 20];

        let identity_keys = IdentitySecretKey::<K>::random_from_rng(rng);

        let pk = IdentityPublicKey::<K>::from(&identity_keys);

        Self::new_from_key(identity_keys)
    }

    pub async fn wrap<T>(self, stream: T) -> Result<O5Stream<T, K>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session = self.new_server_session()?;
        let deadline = self.handshake_timeout.map(|d| Instant::now() + d);
        let mut null_extension_handler = |_: &[NtorV3Extension]| None;

        session
            .handshake(&self, stream, &mut null_extension_handler, deadline)
            .await
    }

    pub fn set_args(&mut self, args: &dyn std::any::Any) -> Result<&Self> {
        Ok(self)
    }

    pub fn new_from_statefile() -> Result<Self> {
        Err(Error::NotImplemented)
    }

    pub fn write_statefile(f: std::fs::File) -> Result<()> {
        Err(Error::NotImplemented)
    }

    pub fn client_params(&self) -> ClientBuilder<K, D> {
        ClientBuilder::<K, D> {
            node_details: Some(self.identity_keys.pk.clone()),
            statefile_path: None,
            handshake_timeout: MaybeTimeout::Default_,
            _digest: PhantomData::<D>,
        }
    }

    pub(crate) fn new_server_session(&self) -> Result<ServerSession<Initialized>> {
        let mut session_id = [0u8; SESSION_ID_LEN];
        rand::thread_rng().fill_bytes(&mut session_id);
        Ok(ServerSession {
            // fixed by server
            biased: self.biased,

            // generated per session
            session_id: session_id.into(),
            len_seed: drbg::Seed::new().unwrap(),
            ipt_seed: drbg::Seed::new().unwrap(),

            _state: Initialized {},
        })
    }

    pub(crate) fn get_identity(&self) -> IdentityPublicKey<K> {
        self.identity_keys.pk.clone()
    }

    pub(crate) fn protocol_id<'a>() -> String {
        let mut id = transport_name!().to_owned();
        id.push('_');
        id.push_str(K::NAME);
        id.push('_');
        id.push_str(D::NAME);
        id
    }
}

#[cfg(test)]
mod tests {
    use crate::dev;

    use super::*;

    use kemeleon::MlKem768;
    use ptrs::trace;
    use sha3::Sha3_256;
    use tokio::net::TcpStream;

    use crate::test_utils::init_subscriber;

    #[test]
    fn parse_json_state() -> Result<()> {
        init_subscriber();

        let mut args = Args::new();
        let test_state = format!(
            r#"{{"{NODE_ID_ARG}": "00112233445566778899", "{PRIVATE_KEY_ARG}":"0123456789abcdeffedcba9876543210", "{SEED_ARG}": "abcdefabcdefabcdefabcdef"}}"#
        );
        ServerBuilder::<TcpStream, MlKem768, Sha3_256>::server_state_from_json(
            test_state.as_bytes(),
            &mut args,
        )?;
        debug!("{:?}\n{}", args.encode_smethod_args(), test_state);

        Ok(())
    }
}
