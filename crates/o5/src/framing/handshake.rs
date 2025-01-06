use crate::{
    common::utils::{get_epoch_hour, make_pad},
    constants::*,
    framing::FrameError,
    handshake::{
        encrypt, Authcode, CHSMaterials, EphemeralPub, HandshakeEphemeralSecret,
        NtorV3Client as Client, SHSMaterials,
    },
    Digest, Result,
};

use bytes::{BufMut, BytesMut};
use hmac::{Mac, SimpleHmac};
use kem::Encapsulate;
use kemeleon::{Encode, OKemCore};
use ptrs::trace;
use rand::Rng;
use rand_core::CryptoRngCore;
use tor_bytes::{EncodeError, EncodeResult, Writer};
use tor_cell::relaycell::extend::NtorV3Extension;
use zeroize::Zeroizing;

use core::borrow::Borrow;
use core::marker::PhantomData;

// -----------------------------[ Server ]-----------------------------

/// Trait allowing for interchangeable server handshake state based on context
pub trait ShsState {}

/// Used by the client when parsing the handshake sent by the server.
pub struct ServerHandshakeMessage<K: OKemCore, D: Digest, S: ShsState> {
    server_ciphertext: K::Ciphertext,
    server_auth: Authcode<D>,
    state: S,
    _digest: PhantomData<D>,
}

/// State tracked when constructing and sending an outgoing server handshake
pub struct ServerStateOutgoing<'a, D: Digest> {
    pub(crate) pad_len: usize,
    // pub(crate) epoch_hour: String, // I don't think this needs stored by the server on send
    /// Ciphertext created as part of the KEM handshake where the server uses the encapsulation key
    /// sent by the client in the client hallo message to share a session shared secret.
    pub(crate) ephemeral_secret: HandshakeEphemeralSecret<D>,
    pub(crate) encrypted_extension_reply: Vec<u8>,
    pub(crate) hs_materials: &'a SHSMaterials,
}
impl<D: Digest> ShsState for ServerStateOutgoing<'_, D> {}

/// State tracked when parsing and operating on an incoming server handshake
pub struct ServerStateIncoming {}
impl ShsState for ServerStateIncoming {}

impl<'a, D: Digest, K: OKemCore, S: ShsState> ServerHandshakeMessage<K, D, S> {
    pub fn new(server_ciphertext: K::Ciphertext, server_auth: Authcode<D>, state: S) -> Self {
        Self {
            server_ciphertext,
            server_auth,
            state,
            _digest: PhantomData,
        }
    }
}

impl<'a, D: Digest, K: OKemCore> ServerHandshakeMessage<K, D, ServerStateOutgoing<'a, D>> {
    /// Serialize the Server Hello Message
    ///
    /// Given a properly processed client handshake, the Server handshake is then constructed as:
    ///
    ///    MSG = Enc_chacha20poly1305(ES, [extensions])
    ///    AUTH = F1(FS, context | PROTOID | ":server_mac")
    ///    Ms = F1(ES, CTso | ":ms")
    ///    MACs = F1(ES, CTso | auth | MSG | Ps | Ms | E | ":mac_s" )
    ///    OUT = CTso | auth | MSG | Ps | Ms | MACs
    ///
    /// where
    ///     EKc   client's encapsulation key NOT obfuscated
    ///     CTc   client ciphertext encoded NOT obfuscated
    ///     EKs   server's Identity Encapsulation key NOT obfuscated
    ///     CTs   ciphertext created by the server using the client session key NOT obfuscated
    ///     CTso  ciphertext created by the server using the client session key, obfuscated
    ///     Ps    N ∈ [serverMinPadLength,serverMaxPadLength] bytes of random padding.
    ///     E     string representation of the number of hours since the UNIX epoch
    pub fn marshall(&self, rng: &mut impl CryptoRngCore, buf: &mut impl BufMut) -> Result<()> {
        // -------------------------------- [ ST-PQ-OBFS ] -------------------------------- //
        // Security Theoretic, KEM, Obfuscated Key exchange

        trace!("serializing server handshake");

        let ephemeral_secret = &self.state.ephemeral_secret;

        let ciphertext = &self.server_ciphertext;

        // set up our hash fn
        let mut f1_es = SimpleHmac::<D>::new_from_slice(ephemeral_secret.as_ref())
            .expect("keying hmac should never fail");

        // compute the Mark
        let mark = {
            f1_es.reset();
            f1_es.update(&ciphertext.as_bytes());
            f1_es.update(SERVER_MARK_ARG);
            f1_es.finalize_reset().into_bytes()
        };

        // Generate the padding
        let pad = make_pad(rng, self.state.pad_len);

        // Write CTso, AUTH, MSG_REPLY, P_s, M_s
        let hello_msg = {
            let mut hello_msg = Vec::new();
            hello_msg
                .write(&ciphertext.as_bytes()[..])
                .and_then(|_| hello_msg.write(&self.server_auth[..]))
                .and_then(|_| hello_msg.write(&self.state.encrypted_extension_reply))
                .and_then(|_| hello_msg.write(&pad))
                .and_then(|_| hello_msg.write(&mark))
                .map_err(|_| {
                    FrameError::FailedToMarshall("failed to encode server handshake".into())
                })?;
            hello_msg
        };
        buf.put(hello_msg.as_slice());

        // Calculate and write MAC
        let mac = {
            f1_es.reset();
            f1_es.update(&hello_msg);
            f1_es.update(get_epoch_hour().to_string().as_bytes());
            f1_es.update(SERVER_MAC_ARG);
            f1_es.finalize_reset().into_bytes()
        };
        buf.put(&mac[..]);

        trace!(
            "{} - mark: {}, mac: {}",
            self.state.hs_materials.session_id,
            hex::encode(mark),
            hex::encode(mac)
        );

        // //------------------------------------[NTORv3]-------------------------------

        // let (enc_key, keystream) = {
        //     let mut xof = DigestWriter(Shake256::default());
        //     xof.write(&T_FINAL)
        //         .and_then(|_| xof.write(&ntor_key_seed))
        //         .map_err(into_internal!("can't generate ntor3 xof."))?;
        //     let mut r = xof.take().finalize_xof();
        //     let mut enc_key = Zeroizing::new([0_u8; ENC_KEY_LEN]);
        //     r.read(&mut enc_key[..]);
        //     (enc_key, r)
        // };

        Ok(())
    }
}

// -----------------------------[ Client ]-----------------------------

/// Preliminary message sent in an obfs4 handshake attempting to open a
/// connection from a client to a potential server.
pub struct ClientHandshakeMessage<K: OKemCore, S: ChsState> {
    client_session_pubkey: EphemeralPub<K>,
    state: S,

    // only used when parsing (i.e. on the server side)
    pub(crate) epoch_hour: String,
}

/// Trait allowing for interchangeable client handshake state based on context
pub trait ChsState {}

/// State tracked when constructing and sending an outgoing client handshake
pub struct ClientStateOutgoing<K: OKemCore> {
    pub(crate) hs_materials: CHSMaterials<K>,
}
impl<K: OKemCore> ChsState for ClientStateOutgoing<K> {}

/// State tracked when parsing and operating on an incoming client handshake
pub struct ClientStateIncoming<D: Digest> {
    ephemeral_secret: HandshakeEphemeralSecret<D>,
    extensions: Vec<NtorV3Extension>,
}
impl<D: Digest> ChsState for ClientStateIncoming<D> {}

impl<D: Digest> ClientStateIncoming<D> {
    pub(crate) fn new(ephemeral_secret: HandshakeEphemeralSecret<D>) -> Self {
        Self {
            ephemeral_secret,
            extensions: Vec::new(),
        }
    }
}

impl<K, D: Digest> ClientHandshakeMessage<K, ClientStateIncoming<D>>
where
    K: OKemCore,
    <K as OKemCore>::EncapsulationKey: Clone, // TODO: Is this necessary?
{
    pub(crate) fn new(
        client_session_pubkey: EphemeralPub<K>,
        state: ClientStateIncoming<D>,
        epoch_hour: Option<String>,
    ) -> Self {
        Self {
            client_session_pubkey,
            state,
            epoch_hour: epoch_hour.unwrap_or(get_epoch_hour().to_string()),
        }
    }

    pub(crate) fn get_ephemeral_secret(&self) -> HandshakeEphemeralSecret<D> {
        self.state.ephemeral_secret.clone()
    }

    pub(crate) fn get_extensions(&self) -> Vec<u8> {
        vec![] // TODO: Flesh out extension serialization
    }
}

impl<K: OKemCore, S: ChsState> ClientHandshakeMessage<K, S>
where
    K: OKemCore,
{
    pub fn get_public(&mut self) -> EphemeralPub<K> {
        self.client_session_pubkey.clone()
    }

    /// return the epoch hour used in the ntor handshake.
    pub fn get_epoch_hr(&self) -> String {
        self.epoch_hour.clone()
    }
}

impl<K> ClientHandshakeMessage<K, ClientStateOutgoing<K>>
where
    K: OKemCore,
{
    pub(crate) fn new(
        client_session_pubkey: EphemeralPub<K>,
        state: ClientStateOutgoing<K>,
    ) -> Self {
        Self {
            client_session_pubkey,
            state,

            // only used when parsing (i.e. on the server side)
            epoch_hour: get_epoch_hour().to_string(),
        }
    }

    /// The client handshake is constructed as:
    ///    ES = F2(NodeID, shared_secret_1)
    ///    MSG = Enc_chacha20poly1305(ES, [extensions])
    ///    Mc = F1(ES, EKco | CTco | ":mc")
    ///    MACc = F1(ES, EKco | CTco | MSG | P_C | Mc | E | ":mac_c" )
    ///    OUT = EKco | CTco | MSG | P_C | Mc | MACc
    ///
    /// where
    ///    EKco is the client's ephemeral encapsulation key encoded in obfuscated form
    ///    CTco is  client_ciphertext_obfuscated
    ///    E is the string representation of the number of hours since the UNIX epoch.
    ///    P_C is [clientMinPadLength,clientMaxPadLength] bytes of random padding.
    pub fn marshall<D: Digest>(
        &mut self,
        rng: &mut impl CryptoRngCore,
        buf: &mut impl BufMut,
    ) -> EncodeResult<HandshakeEphemeralSecret<D>> {
        trace!("serializing client handshake");
        self.marshall_inner::<D>(rng, buf)
    }

    fn marshall_inner<D: Digest>(
        &mut self,
        rng: &mut impl CryptoRngCore,
        buf: &mut impl BufMut,
    ) -> EncodeResult<HandshakeEphemeralSecret<D>> {
        // serialize our extensions into a message
        let mut message = BytesMut::new();
        NtorV3Extension::write_many_onto(self.state.hs_materials.aux_data.borrow(), &mut message)?;

        // -------------------------------- [ ST-PQ-OBFS ] -------------------------------- //
        // Security Theoretic, Post-Quantum safe, Obfuscated Key exchange

        let node_encap_key = &self.state.hs_materials.node_pubkey.ek;
        let node_id = &self.state.hs_materials.node_pubkey.id;
        let (ciphertext, shared_secret) = node_encap_key.encapsulate(rng).map_err(to_tor_err)?;

        // compute our ephemeral secret
        let mut f2 = SimpleHmac::<D>::new_from_slice(node_id.as_bytes())
            .expect("keying hmac should never fail");

        let ephemeral_secret = {
            f2.reset();
            f2.update(&shared_secret.as_bytes()[..]);
            Zeroizing::new(f2.finalize_reset().into_bytes())
        };

        // set up our hash fn
        let mut f1_es = SimpleHmac::<D>::new_from_slice(ephemeral_secret.as_ref())
            .expect("keying hmac should never fail");

        // compute the Mark
        let mark = {
            f1_es.reset();
            f1_es.update(&self.client_session_pubkey.as_bytes()[..]);
            f1_es.update(&ciphertext.as_bytes()[..]);
            f1_es.update(CLIENT_MARK_ARG);
            f1_es.finalize_reset().into_bytes()
        };

        // Encrypt the message (Extensions etc.)
        //
        // note that these do not benefit from forward secrecy, i.e. if the servers long term
        // identity secret key is leaked this text can be decrypted. Once we receive the
        // server response w/ secrets based on ephemeral (session) secrets any further data has
        // forward secrecy.
        let encrypted_msg = encrypt::<D>(&ephemeral_secret, &message);

        // Generate the padding
        let pad_len = rng.gen_range(MIN_PAD_LENGTH..Client::<K, D>::CLIENT_MAX_PAD_LENGTH); // TODO - recalculate these
        let pad = make_pad(rng, pad_len);

        // Write EKco, CTco, MSG, P_C, M_C
        let hello_msg = {
            let mut hello_msg = Vec::new();
            hello_msg.write(&self.client_session_pubkey.as_bytes()[..]);
            hello_msg.write(&ciphertext.as_bytes()[..]);
            hello_msg.write(&encrypted_msg);
            hello_msg.write(&pad);
            hello_msg.write(&mark);
            hello_msg
        };
        buf.put(hello_msg.as_slice());

        // Calculate and write MAC
        f1_es.update(&hello_msg);
        self.epoch_hour = format!("{}", get_epoch_hour());
        f1_es.update(self.epoch_hour.as_bytes());
        f1_es.update(CLIENT_MAC_ARG);
        let mac = f1_es.finalize_reset().into_bytes();
        buf.put(&mac[..]);

        trace!(
            "{} - mark: {}, mac: {}",
            self.state.hs_materials.session_id,
            hex::encode(mark),
            hex::encode(mac)
        );

        Ok(ephemeral_secret)
    }
}

fn to_tor_err(e: impl core::fmt::Debug) -> EncodeError {
    tor_bytes::EncodeError::from(tor_error::Bug::new(
        tor_error::ErrorKind::Other,
        format!("cryptographic encapsulation error: {e:?}"),
    ))
}
