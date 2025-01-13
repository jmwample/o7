use crate::{
    common::{
        discard, drbg,
        ntor_arti::{
            ClientHandshake, ClientHandshakeComplete, RelayHandshakeError, SessionID,
            SessionIdentifier,
        },
    },
    constants::*,
    framing::O5Codec,
    handshake::{
        CHSMaterials, ClientHsComplete, IdentityPublicKey, NtorV3Client, NtorV3KeyGen,
        NtorV3KeyGenerator,
    },
    msgs::Messages,
    proto::{O5Stream, ObfuscatedStream},
    sessions::{Established, Fault, Initialized, Session},
    traits::OKemCore,
    Digest, Error, Result,
};

use std::{
    io::{Error as IoError, ErrorKind as IoErrorKind},
    marker::PhantomData,
};

use bytes::{BufMut, BytesMut};
use kemeleon::Encode;
use ptrs::{debug, info};
use rand_core::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tokio_util::codec::Decoder;

// ================================================================ //
//                       Client States                              //
// ================================================================ //

pub(crate) struct ClientSession<S: ClientSessionState, K: OKemCore> {
    node_pubkey: IdentityPublicKey<K>,
    session_id: SessionID,
    epoch_hour: String,

    biased: bool,

    len_seed: drbg::Seed,

    _state: S,
}

#[allow(unused)]
struct ClientHandshakeFailed {
    details: String,
}

struct ClientHandshaking {}

pub(crate) trait ClientSessionState {}
impl ClientSessionState for Initialized {}
impl ClientSessionState for ClientHandshaking {}
impl ClientSessionState for Established {}

impl ClientSessionState for ClientHandshakeFailed {}
impl Fault for ClientHandshakeFailed {}

impl<S: ClientSessionState, K: OKemCore> ClientSession<S, K> {
    pub fn session_id(&self) -> String {
        String::from("c-") + &self.session_id.to_string()
    }

    pub(crate) fn set_session_id(&mut self, id: SessionID) {
        debug!("{} -> {} client updating session id", self.session_id, id);
        self.session_id = id;
    }

    pub(crate) fn biased(&self) -> bool {
        self.biased
    }

    pub fn len_seed(&self) -> drbg::Seed {
        self.len_seed.clone()
    }

    /// Helper function to perform state transitions.
    fn transition<T: ClientSessionState>(self, t: T) -> ClientSession<T, K> {
        ClientSession {
            node_pubkey: self.node_pubkey,
            session_id: self.session_id,
            epoch_hour: self.epoch_hour,
            biased: self.biased,

            len_seed: self.len_seed,
            _state: t,
        }
    }

    /// Helper function to perform state transitions.
    fn fault<F: Fault + ClientSessionState>(self, f: F) -> ClientSession<F, K> {
        ClientSession {
            node_pubkey: self.node_pubkey,
            session_id: self.session_id,
            epoch_hour: self.epoch_hour,
            biased: self.biased,

            len_seed: self.len_seed,
            _state: f,
        }
    }
}

pub fn new_client_session<K: OKemCore>(
    station_pubkey: IdentityPublicKey<K>,
) -> ClientSession<Initialized, K> {
    let mut session_id = [0u8; SESSION_ID_LEN];
    rand::thread_rng().fill_bytes(&mut session_id);
    ClientSession {
        node_pubkey: station_pubkey,
        session_id: session_id.into(),
        epoch_hour: "".into(),
        biased: false,

        len_seed: drbg::Seed::new().unwrap(),
        _state: Initialized,
    }
}

impl<K: OKemCore> ClientSession<Initialized, K> {
    /// Perform a Handshake over the provided stream.
    ///
    /// Completes the client handshake including sending the initial hello message
    /// and processing the response (or lack thereof). On success this returns:
    ///     1) The remaining bytes included in the server response not part of the
    /// handshake packet.
    /// TODO: should 1 &2 be combined?
    ///     2) Any sever extensions sent as part of the handshake response
    ///     3) An NtorV3-Like key generator used to bootstrap the codec that will
    /// be used to obfuscate the stream data.
    ///
    /// Errors can be cause by:
    /// - failing to connect to remote host (timeout)
    /// - failing to write the handshake
    /// - timeout / cancel while waiting for response
    /// - failing to read response
    /// - crypto error in response
    /// - response fails server auth check
    ///
    /// TODO: make sure failure modes are understood (FIN/RST w/ and w/out buffered data, etc.)
    pub async fn handshake<T, D>(
        self,
        mut stream: T,
        deadline: Option<Instant>,
    ) -> Result<O5Stream<T, K>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        D: Digest,
    {
        // set up for handshake
        let mut session = self.transition(ClientHandshaking {});

        let materials = CHSMaterials::new(&session.node_pubkey, session.session_id());

        // default deadline
        let d_def = Instant::now() + CLIENT_HANDSHAKE_TIMEOUT;
        let handshake_fut = Self::complete_handshake::<T, D>(stream, materials, deadline);
        let (mut hs_complete, mut stream) =
            match tokio::time::timeout_at(deadline.unwrap_or(d_def), handshake_fut).await {
                Ok(result) => match result {
                    Ok(handshake) => handshake,
                    Err(e) => {
                        // non-timeout error,
                        let id = session.session_id();
                        let _ = session.fault(ClientHandshakeFailed {
                            details: format!("{id} handshake failed {e}"),
                        });
                        return Err(e);
                    }
                },
                Err(_) => {
                    let id = session.session_id();
                    let _ = session.fault(ClientHandshakeFailed {
                        details: format!("{id} timed out"),
                    });
                    return Err(Error::HandshakeTimeout);
                }
            };

        // post-handshake state updates
        let mut keygen: NtorV3KeyGenerator = hs_complete.keygen();
        session.set_session_id(keygen.session_id());
        let mut codec: O5Codec = keygen.into();

        // // TODO: handle server response extensions here
        // for ext in hs_complete.extensions() {
        //      // do something
        // }

        let res = codec.decode(&mut hs_complete.remainder());
        if let Ok(Some(Messages::PrngSeed(seed))) = res {
            // try to parse the remainder of the server hello packet as a
            // PrngSeed since it should be there.
            let len_seed = drbg::Seed::from(seed);
            session.set_len_seed(len_seed);
        } else {
            debug!("NOPE {res:?}");
        }

        // mark session as Established
        let session_state: ClientSession<Established, K> = session.transition(Established {});
        info!("{} handshake complete", session_state.session_id());

        codec.handshake_complete();
        let o4 = ObfuscatedStream::new(stream, codec, Session::Client(session_state));

        Ok(O5Stream::from_o4(o4))
    }

    async fn complete_handshake<T, D>(
        mut stream: T,
        materials: CHSMaterials<K>,
        deadline: Option<Instant>,
    ) -> Result<(
        impl ClientHandshakeComplete<Remainder = BytesMut, KeyGen = NtorV3KeyGenerator>,
        T,
    )>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        D: Digest,
    {
        // let session_id = materials.session_id;
        let mut chs_message = BytesMut::new();
        let mut state = NtorV3Client::<K, D>::client1(materials, &mut chs_message)?;
        // let mut file = tokio::fs::File::create("message.hex").await?;
        // file.write_all(&chs_message).await?;
        stream.write_all(&chs_message).await?;

        debug!(
            "{} handshake sent {}B, waiting for sever response",
            state.materials.session_id,
            chs_message.len()
        );

        let mut buf = [0u8; MAX_PACKET_LENGTH];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                Err(Error::IOError(IoError::new(
                    IoErrorKind::UnexpectedEof,
                    "read 0B in client handshake",
                )))?
            }
            debug!(
                "{} read {n}/{}B of server handshake",
                state.materials.session_id,
                buf.len()
            );

            match NtorV3Client::client2(&mut state, &buf[..n]) {
                Ok(r) => return Ok((r, stream)),
                Err(Error::HandshakeErr(RelayHandshakeError::EAgain)) => continue,
                Err(e) => {
                    // if a deadline was set and has not passed already, discard
                    // from the stream until the deadline, then close.
                    if deadline.is_some_and(|d| d > Instant::now()) {
                        debug!("{} discarding due to: {e}", state.materials.session_id);
                        discard(&mut stream, deadline.unwrap() - Instant::now()).await?;
                    }
                    stream.shutdown().await?;
                    return Err(e);
                }
            }
        }
    }
}

impl<K: OKemCore> ClientSession<ClientHandshaking, K> {
    pub(crate) fn set_len_seed(&mut self, seed: drbg::Seed) {
        debug!(
            "{} setting length seed {}",
            self.session_id(),
            hex::encode(seed.as_bytes())
        );
        self.len_seed = seed;
    }
}

impl<S: ClientSessionState, K: OKemCore> std::fmt::Debug for ClientSession<S, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[ id:{}, ident_pk:{}, epoch_hr:{} ]",
            hex::encode(self.node_pubkey.id.as_bytes()),
            hex::encode(self.node_pubkey.ek.as_bytes()),
            self.epoch_hour,
        )
    }
}
