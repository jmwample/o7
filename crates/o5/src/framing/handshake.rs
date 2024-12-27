use crate::{
    common::{
        utils::{get_epoch_hour, make_pad},
        HmacSha256,
    },
    constants::*,
    handshake::{
        decrypt, encrypt, Authcode, CHSMaterials, EphemeralKey, EphemeralPub, SessionSharedSecret,
        AUTHCODE_LENGTH, ENC_KEY_LEN,
    },
    Digest, Error, Result,
};

use block_buffer::Eager;
use bytes::{BufMut, BytesMut};
use digest::{
    core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    Digest as _, HashMarker,
};
use hmac::{Mac, SimpleHmac};
use kem::{Decapsulate, Encapsulate};
use kemeleon::{Encode, OKemCore};
use ptrs::trace;
use rand::Rng;
use rand_core::CryptoRngCore;
use sha3::Sha3_256;
use tor_bytes::{EncodeError, EncodeResult};
use tor_cell::relaycell::extend::NtorV3Extension;
use typenum::{
    consts::U256, marker_traits::NonZero, operator_aliases::Le, type_operators::IsLess, Unsigned,
};
use zeroize::{Zeroize, Zeroizing};

use core::borrow::Borrow;

// -----------------------------[ Server ]-----------------------------

/// Used by the client when parsing the handshake sent by the server.
pub struct ServerHandshakeMessage<K: OKemCore> {
    server_auth: [u8; AUTHCODE_LENGTH],
    pad_len: usize,
    session_pubkey: EphemeralPub<K>,
    epoch_hour: String,
    aux_data: Vec<NtorV3Extension>,
    client_hadshake_msg: ClientHandshakeMessage<K, ClientStateIncoming>,
}

impl<K: OKemCore> ServerHandshakeMessage<K> {
    pub fn with_pad_len(&mut self, pad_len: usize) -> &Self {
        self.pad_len = pad_len;
        self
    }

    pub fn with_aux_data(&mut self, aux_data: Vec<NtorV3Extension>) -> &Self {
        self.aux_data = aux_data;
        self
    }

    pub fn server_pubkey(&mut self) -> EphemeralPub<K> {
        self.session_pubkey.clone()
    }

    pub fn server_auth(self) -> Authcode {
        self.server_auth
    }

    /// Serialize the Server Hello Message
    ///
    /// Process the dlient handshake to capture required secrets and auth context.
    /// The Server handshake is then constructed as:
    ///
    ///    shared_secret_1 = Decapsulate(DK_id, ct)
    ///
    ///    CTs, shared_secret_2 = Encapsulate(EKc)
    ///
    ///    ES = F2(NodeID, shared_secret_1)
    ///    ES' = F1(ES, ":derive_key")
    ///    FS = F2(ES', shared_secret_2)
    ///    SESSION_KEY = F1(FS, EKs | CTc | EKc | CTs | PROTOID | ":key_extract")
    ///
    ///    MSG = Enc_chacha20poly1305(ES, [extensions])
    ///    auth = F1(FS, EKs | CTc | EKc | CTs | PROTOID | ":server_mac")
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
    pub fn marshall(&mut self, _buf: &mut impl BufMut) -> Result<()> {
        trace!("serializing server handshake");

        // -------------------------------- [ ST-PQ-OBFS ] -------------------------------- //
        // Security Theoretic, Post-Quantum safe, Obfuscated Key exchange

        // let (ciphertext, shared_secret) = node_encap_key.encapsulate(rng).map_err(to_tor_err)?;

        // h.update(self.session_pubkey.as_bytes().as_ref());
        // let mark: &[u8] = &h.finalize_reset().into_bytes()[..MARK_LENGTH];

        // // Generate the padding
        // let pad: &[u8] = &make_pad(rng, self.pad_len)?;

        // // Write Y, AUTH, P_S, M_S.
        // let mut params = vec![];
        // params.extend_from_slice(self.session_pubkey.as_bytes());
        // params.extend_from_slice(&self.server_auth);
        // params.extend_from_slice(pad);
        // params.extend_from_slice(mark);
        // buf.put(params.as_slice());

        // // Calculate and write MAC
        // h.update(&params);
        // h.update(self.epoch_hour.as_bytes());
        // buf.put(&h.finalize_reset().into_bytes()[..MAC_LENGTH]);

        // //------------------------------------[NTORv3]-------------------------------

        // let secret_input = {
        //     let mut si = SecretBuf::new();
        //     si.write(&xy.as_bytes())
        //         .and_then(|_| si.write(&xb.as_bytes()))
        //         .and_then(|_| si.write(&keypair.pk.id))
        //         .and_then(|_| si.write(&keypair.pk.pk.as_bytes()))
        //         .and_then(|_| si.write(&client_pk.as_bytes()))
        //         .and_then(|_| si.write(&y_pk.as_bytes()))
        //         .and_then(|_| si.write(PROTOID))
        //         .and_then(|_| si.write(&Encap(verification)))
        //         .map_err(into_internal!("can't derive ntor3 secret_input"))?;
        //     si
        // };
        // let ntor_key_seed = h_key_seed(&secret_input);
        // let verify = h_verify(&secret_input);

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
        // let encrypted_reply = encrypt(&enc_key, &reply);
        // let auth: DigestVal = {
        //     let mut auth = DigestWriter(Sha3_256::default());
        //     auth.write(&T_AUTH)
        //         .and_then(|_| auth.write(&verify))
        //         .and_then(|_| auth.write(&keypair.pk.id))
        //         .and_then(|_| auth.write(&keypair.pk.pk.as_bytes()))
        //         .and_then(|_| auth.write(&y_pk.as_bytes()))
        //         .and_then(|_| auth.write(&client_pk.as_bytes()))
        //         .and_then(|_| auth.write(&msg_mac))
        //         .and_then(|_| auth.write(&Encap(&encrypted_reply)))
        //         .and_then(|_| auth.write(PROTOID))
        //         .and_then(|_| auth.write(&b"Server"[..]))
        //         .map_err(into_internal!("can't derive ntor3 authentication"))?;
        //     auth.take().finalize().into()
        // };

        // let reply = {
        //     let mut reply = Vec::new();
        //     reply
        //         .write(&y_pk.as_bytes())
        //         .and_then(|_| reply.write(&auth))
        //         .and_then(|_| reply.write(&encrypted_reply))
        //         .map_err(into_internal!("can't encode ntor3 reply."))?;
        //     reply
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
pub struct ClientStateIncoming {
    ephemeral_secret: Zeroizing<[u8; 32]>,
}
impl ChsState for ClientStateIncoming {}

impl ClientStateIncoming {
    pub(crate) fn new(ephemeral_secret: Zeroizing<[u8; 32]>) -> Self {
        Self { ephemeral_secret }
    }
}

impl<K> ClientHandshakeMessage<K, ClientStateIncoming>
where
    K: OKemCore,
    <K as OKemCore>::EncapsulationKey: Clone, // TODO: Is this necessary?
{
    pub(crate) fn new(
        client_session_pubkey: EphemeralPub<K>,
        state: ClientStateIncoming,
        epoch_hour: Option<String>,
    ) -> Self {
        Self {
            client_session_pubkey,
            state,
            epoch_hour: epoch_hour.unwrap_or(get_epoch_hour().to_string()),
        }
    }

    pub(crate) fn get_ephemeral_secret(&self) -> Zeroizing<[u8; 32]> {
        self.state.ephemeral_secret.clone()
    }
}

impl<K: OKemCore, S: ChsState> ClientHandshakeMessage<K, S>
where
    K: OKemCore,
{
    pub fn get_public(&mut self) -> EphemeralPub<K> {
        // trace!("repr: {}", hex::encode(self.client_session_pubkey.id);
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
    pub fn marshall(
        &mut self,
        rng: &mut impl CryptoRngCore,
        buf: &mut impl BufMut,
    ) -> EncodeResult<Zeroizing<[u8; ENC_KEY_LEN]>> {
        trace!("serializing client handshake");
        self.marshall_inner::<Sha3_256>(rng, buf)
    }

    fn marshall_inner<D: Digest>(
        &mut self,
        rng: &mut impl CryptoRngCore,
        buf: &mut impl BufMut,
    ) -> EncodeResult<Zeroizing<[u8; ENC_KEY_LEN]>> {
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
        f2.update(&shared_secret.as_bytes()[..]);
        let mut ephemeral_secret = Zeroizing::new([0u8; ENC_KEY_LEN]);
        ephemeral_secret.copy_from_slice(&f2.finalize_reset().into_bytes()[..ENC_KEY_LEN]);

        // set up our hash fn
        let mut f1_es = SimpleHmac::<D>::new_from_slice(ephemeral_secret.as_ref())
            .expect("keying hmac should never fail");

        // compute the Mark
        f1_es.update(&self.client_session_pubkey.as_bytes()[..]);
        f1_es.update(&ciphertext.as_bytes()[..]);
        f1_es.update(CLIENT_MARK_ARG);
        let mark = f1_es.finalize_reset().into_bytes();

        // Encrypt the message (Extensions etc.)
        //
        // note that these do not benefit from forward secrecy, i.e. if the servers long term
        // identity secret key is leaked this text can be decrypted. Once we receive the
        // server response w/ secrets based on ephemeral (session) secrets any further data has
        // forward secrecy.
        let encrypted_msg = encrypt(&ephemeral_secret, &message);

        // Generate the padding
        let pad_len = rng.gen_range(CLIENT_MIN_PAD_LENGTH..CLIENT_MAX_PAD_LENGTH); // TODO - recalculate these
        let pad = make_pad(rng, pad_len);

        // Write EKco, CTco, MSG, P_C, M_C
        let mut params = vec![];
        params.extend_from_slice(&self.client_session_pubkey.as_bytes()[..]);
        params.extend_from_slice(&ciphertext.as_bytes()[..]);
        params.extend_from_slice(&message);
        params.extend_from_slice(&pad);
        params.extend_from_slice(&mark);
        buf.put(params.as_slice());

        // Calculate and write MAC
        f1_es.update(&params);
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
// The client handshake is X | P_C | M_C | MAC(X | P_C | M_C | E) where:
//  * X is the client's ephemeral Curve25519 public key representative.
//  * P_C is [clientMinPadLength,clientMaxPadLength] bytes of random padding.
//  * M_C is HMAC-SHA256-128(serverIdentity | NodeID, X)
//  * MAC is HMAC-SHA256-128(serverIdentity | NodeID, X .... E)
//  * E is the string representation of the number of hours since the UNIX epoch.
