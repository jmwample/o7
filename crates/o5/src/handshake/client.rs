//! Client specific handshake handling implementations.

use std::marker::PhantomData;
use std::time::Instant;

use crate::{
    common::{
        ct,
        ntor_arti::{
            ClientHandshake, ClientHandshakeComplete, ClientHandshakeMaterials, KeyGenerator,
            RelayHandshakeError, RelayHandshakeResult,
        },
        utils::{find_mac_mark, get_epoch_hour},
    },
    constants::*,
    framing::handshake::{
        ClientHandshakeMessage, ClientStateOutgoing, ServerHandshakeMessage, ServerStateIncoming,
    },
    handshake::{keys::*, *},
    traits::{DigestSizes, FramingSizes},
    Digest, Error, Result, Server,
};

use bytes::{BufMut, BytesMut};
use digest::CtOutput;
use hmac::{Mac, SimpleHmac};
use kem::{Decapsulate, Encapsulate};
use kemeleon::{Encode, OKemCore};
use ptrs::{debug, trace};
use rand::{CryptoRng, Rng, RngCore};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use tor_bytes::{EncodeResult, Reader, SecretBuf, Writer};
use tor_cell::relaycell::extend::NtorV3Extension;
use tor_error::into_internal;
use tor_llcrypto::{
    d::{Sha3_256, Shake256, Shake256Reader},
    pk::ed25519::Ed25519Identity,
};
use typenum::Unsigned;
use zeroize::Zeroizing;

/// Client state for the o5 (ntor v3) handshake.
///
/// The client needs to hold this state between when it sends its part
/// of the handshake and when it receives the relay's reply.
pub(crate) struct HandshakeState<K: OKemCore, D: Digest> {
    /// The temporary curve25519 secret (x) that we've generated for
    /// this handshake.
    my_sk: EphemeralKey<K>,

    /// handshake materials
    pub(crate) materials: HandshakeMaterials<K>,

    /// the computed hour at which the initial portion of the handshake was sent.
    epoch_hr: String,

    /// The shared secret generated as F2(node_id, encapsulation_key)
    ephemeral_secret: HandshakeEphemeralSecret<D>,

    /// client hello message that we sent, used again after receiving the server hello.
    client_hs_msg: BytesMut,
}

impl<K: OKemCore, D: Digest> HandshakeState<K, D> {
    fn node_pubkey(&self) -> &<K as OKemCore>::EncapsulationKey {
        &self.materials.node_pubkey.ek
    }

    fn node_id(&self) -> Ed25519Identity {
        self.materials.node_pubkey.id
    }
}

/// Materials required to initiate a handshake from the client role.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HandshakeMaterials<K: OKemCore> {
    pub(crate) node_pubkey: IdentityPublicKey<K>,
    pub(crate) session_id: String,
    pub(crate) aux_data: Vec<NtorV3Extension>,
}

impl<K: OKemCore> HandshakeMaterials<K> {
    pub(crate) fn new(node_pubkey: &IdentityPublicKey<K>, session_id: String) -> Self {
        HandshakeMaterials {
            node_pubkey: node_pubkey.clone(),
            session_id,
            aux_data: vec![],
        }
    }

    pub fn with_early_data(mut self, data: impl AsRef<[NtorV3Extension]>) -> Self {
        self.aux_data = data.as_ref().to_vec();
        self
    }

    pub(crate) fn get_identity(&self) -> IdentityPublicKey<K> {
        self.node_pubkey.clone()
    }
}

impl<K: OKemCore> ClientHandshakeMaterials for HandshakeMaterials<K> {
    type IdentityKeyType = IdentityPublicKey<K>;
    type ClientAuxData = Vec<NtorV3Extension>;

    fn node_pubkey(&self) -> &Self::IdentityKeyType {
        &self.node_pubkey
    }

    fn aux_data(&self) -> Option<&Self::ClientAuxData> {
        Some(&self.aux_data)
    }
}

/// Client side of the ntor v3 handshake.
pub(crate) struct NtorV3Client<K: OKemCore, D: Digest> {
    _okem: PhantomData<K>,
    _digest: PhantomData<D>,
}

/// State resulting from successful client handshake.
pub struct HsComplete {
    xof_reader: NtorV3XofReader,
    extensions: Vec<NtorV3Extension>,
    remainder: BytesMut,
}

impl ClientHandshakeComplete for HsComplete {
    type KeyGen = NtorV3KeyGenerator;
    type ServerAuxData = Vec<NtorV3Extension>;
    type Remainder = BytesMut;
    fn keygen(&self) -> Self::KeyGen {
        NtorV3KeyGenerator::new::<ClientRole>(self.xof_reader.clone())
    }
    fn extensions(&self) -> &Self::ServerAuxData {
        &self.extensions
    }
    fn remainder(&self) -> Self::Remainder {
        self.remainder.clone()
    }
}

impl<K: OKemCore, D: Digest> ClientHandshake for NtorV3Client<K, D> {
    type StateType = HandshakeState<K, D>;
    type HandshakeMaterials = HandshakeMaterials<K>;
    type HsOutput = HsComplete;

    /// Generate a new client onionskin for a relay with a given onion key.
    /// If any `extensions` are provided, encode them into to the onionskin.
    ///
    /// On success, return a state object that will be used to complete the handshake, along
    /// with the message to send.
    fn client1<B: BufMut>(
        hs_materials: Self::HandshakeMaterials,
        out: &mut B,
    ) -> Result<Self::StateType> {
        let mut rng = rand::thread_rng();

        Ok(Self::client_handshake_ntor_v3(&mut rng, hs_materials, out)
            .map_err(into_internal!("Can't encode ntor3 client handshake."))?)
    }

    /// Handle an onionskin from a relay, and produce a key generator.
    ///
    /// The state object must match the one that was used to make the
    /// client onionskin that the server is replying to.
    fn client2<T: AsRef<[u8]>>(state: &mut Self::StateType, msg: T) -> Result<Self::HsOutput> {
        let (message, xof_reader) = Self::client_handshake_ntor_v3_part2(msg, state)?;
        let extensions = NtorV3Extension::decode(&message).map_err(|err| Error::CellDecodeErr {
            object: "ntor v3 extensions",
            err,
        })?;

        Ok(HsComplete {
            xof_reader,
            extensions,
            remainder: BytesMut::new(), // TODO: ACTUALLY FILL THIS WITH REMAINDER BYTES
        })
    }
}

impl<K: OKemCore, D: Digest> NtorV3Client<K, D> {
    const CT_SIZE: usize = K::CT_SIZE;
    const EK_SIZE: usize = K::EK_SIZE;
    const AUTH_SIZE: usize = D::AUTH_SIZE;
    pub const CLIENT_MIN_HANDSHAKE_LENGTH: usize =
        K::EK_SIZE + K::CT_SIZE + D::MARK_SIZE + D::MAC_SIZE;
    pub const CLIENT_MAX_PAD_LENGTH: usize = MAX_PACKET_LENGTH - Self::CLIENT_MIN_HANDSHAKE_LENGTH;

    /// Client-side Ntor version 3 handshake, part one.
    ///
    /// Given a secure `rng`, a relay's public key, a secret message to send, generate a new handshake
    /// state and a message to send to the relay.
    pub(crate) fn client_handshake_ntor_v3<Out: BufMut>(
        rng: &mut impl CryptoRngCore,
        materials: HandshakeMaterials<K>,
        out_buf: &mut Out,
    ) -> EncodeResult<HandshakeState<K, D>> {
        let keys = K::generate(rng);
        Self::client_handshake_ntor_v3_no_keygen(rng, keys, materials, out_buf)
    }

    /// As `client_handshake_ntor_v3`, but don't generate an ephemeral DH
    /// key: instead take that key an arguments `my_sk`.
    ///
    /// (DK, EK , EK1) <-- OKEM.KGen()
    pub(crate) fn client_handshake_ntor_v3_no_keygen<Out: BufMut>(
        rng: &mut impl CryptoRngCore,
        keys: (K::DecapsulationKey, K::EncapsulationKey),
        materials: HandshakeMaterials<K>,
        out_buf: &mut Out,
    ) -> EncodeResult<HandshakeState<K, D>> {
        let ephemeral_ek = EphemeralPub::new(keys.1);
        let hs_materials = ClientStateOutgoing {
            hs_materials: materials.clone(),
        };
        let mut client_msg =
            ClientHandshakeMessage::<K, ClientStateOutgoing<K>>::new(ephemeral_ek, hs_materials);

        // ------------ [ Perform Handshake and Serialize Packet ] ------------ //

        let mut buf = BytesMut::with_capacity(MAX_PACKET_LENGTH);
        let ephemeral_secret = client_msg.marshall::<D>(rng, &mut buf)?;

        out_buf.put(buf.clone());

        let state = HandshakeState {
            materials,
            my_sk: keys::EphemeralKey::new(keys.0),
            ephemeral_secret,
            epoch_hr: client_msg.get_epoch_hr(),
            client_hs_msg: buf,
        };

        Ok(state)
    }

    /// Finalize the handshake on the client side.
    ///
    /// Called after we've received a message from the relay: try to
    /// complete the handshake and verify its correctness.
    ///
    /// On success, return the server's reply to our original encrypted message,
    /// and an `XofReader` to use in generating circuit keys.
    pub(crate) fn client_handshake_ntor_v3_part2(
        relay_handshake: impl AsRef<[u8]>,
        state: &HandshakeState<K, D>,
    ) -> RelayHandshakeResult<(Vec<u8>, NtorV3XofReader)> {
        let msg = relay_handshake.as_ref();
        if Server::<K, D>::SERVER_MIN_HANDSHAKE_LENGTH > msg.len() {
            Err(RelayHandshakeError::EAgain)?;
        }

        let mut server_hs = match Self::try_parse_server_handshake(msg, state) {
            Ok(shs) => shs,
            Err(RelayHandshakeError::EAgain) => {
                return Err(RelayHandshakeError::EAgain);
            }
            Err(_e) => {
                debug!(
                    "{} failed to parse server handshake: {_e}",
                    state.materials.session_id
                );
                return Err(RelayHandshakeError::BadClientHandshake);
            }
        };

        debug!(
            "{} successfully parsed server handshake",
            state.materials.session_id
        );

        // get the chunk containing the ciphertext
        let mut server_ct_obfs = &msg[0..K::CT_SIZE];

        // get the chunk containing the server's authentication
        let mut server_auth = &msg[K::CT_SIZE..K::CT_SIZE + D::AUTH_SIZE];

        // decode and decapsulate the secret encoded by the server
        let server_ct = <K as OKemCore>::Ciphertext::try_from_bytes(server_ct_obfs)
            .map_err(|e| RelayHandshakeError::FailedParse)?;
        let shared_secret_2 = state
            .my_sk
            .decapsulate(&server_ct)
            .map_err(|e| RelayHandshakeError::FailedDecapsulation)?;

        let mut f1_es = SimpleHmac::<D>::new_from_slice(state.ephemeral_secret.as_ref())
            .expect("keying hmac should never fail");

        // compute the Session Ephemeral Secret
        let derivation_ephemeral = {
            f1_es.reset();
            f1_es.update(&KEY_DERIVE_ARG);
            f1_es.finalize_reset().into_bytes()
        };

        let mut f2 = SimpleHmac::<D>::new_from_slice(derivation_ephemeral.as_ref())
            .expect("keying hmac should never fail");

        // compute our Combiner Ephemeral Secret
        let combiner_ephemeral = {
            f2.reset();
            f2.update(&shared_secret_2.as_bytes()[..]);
            Zeroizing::new(f2.finalize_reset().into_bytes())
        };

        // Handshake context = EKco || CTco || EKso || CTso || protocol_id
        let mut context = {
            let mut c = SecretBuf::new();

            let client_context_elements = &state.client_hs_msg[K::EK_SIZE..K::EK_SIZE + K::CT_SIZE];
            c.write(client_context_elements) // EKco || CTco from client handshake
                .and_then(|_| c.write(&state.node_pubkey().as_bytes()[..])) // EKso server identity key
                .and_then(|_| c.write(server_ct_obfs)) // CTso server created ciphertext
                .and_then(|_| c.write(Server::<K, D>::protocol_id())) // protocol ID
                .map_err(|_| {
                    RelayHandshakeError::FrameError("failed to wire reply context".into())
                })?;
            c
        };

        let mut f1_fs = SimpleHmac::<D>::new_from_slice(combiner_ephemeral.as_ref())
            .expect("keying hmac should never fail");

        // Compute the Session Key value used to key our cipher.
        let session_key = {
            f1_fs.reset();
            f1_fs.update(&context[..]);
            f1_fs.update(KEY_EXTRACT_ARG);
            Zeroizing::new(f1_fs.finalize_reset().into_bytes())
        };

        // Compute the Server message authentication value
        let computed_auth = {
            f1_fs.reset();
            f1_fs.update(&context[..]);
            f1_fs.update(SERVER_AUTH_ARG);
            f1_fs.finalize_reset().into_bytes()
        };

        let err = match <subtle::Choice as Into<bool>>::into(computed_auth.ct_eq(&server_auth)) {
            // // TODO: If an Ellyptic Curve scheme (i.e. X25519) is involved
            // // make sure that the clients mac matches and that both x25519 keys
            // & ct::bool_to_choice(yx.was_contributory())
            // & ct::bool_to_choice(state.shared_secret.was_contributory());
            true => None,
            false => {
                trace!(
                    "{} != {}",
                    hex::encode(&computed_auth),
                    hex::encode(&server_auth)
                );
                Some(RelayHandshakeError::ServerAuthMismatch)
            }
        };

        let (enc_key, keystream) = {
            use digest::{ExtendableOutput, Update, XofReader};
            let mut xof = Shake256::default();
            xof.update(&T_FINAL);
            xof.update(&session_key);
            let mut r = xof.finalize_xof();
            let mut enc_key = SessionSharedSecret::<D>::default();
            r.read(&mut enc_key[..]);
            (enc_key, r)
        };

        // Decrypt extension messages and give them to the client.
        // TODO PARSE EXTENSIONS
        // let server_reply = decrypt(&enc_key, encrypted_msg);

        if err.is_none() {
            Ok((Vec::new(), NtorV3XofReader::new(keystream)))
        } else {
            Err(err.unwrap())
        }
    }
}

impl<K: OKemCore, D: Digest> NtorV3Client<K, D> {
    fn try_parse_server_handshake(
        b: impl AsRef<[u8]>,
        state: &HandshakeState<K, D>,
    ) -> RelayHandshakeResult<ServerHandshakeMessage<K, D, ServerStateIncoming>> {
        let buf = b.as_ref();

        if Server::<K, D>::SERVER_MIN_HANDSHAKE_LENGTH > buf.len() {
            Err(RelayHandshakeError::EAgain)?;
        }

        let mut server_ct_obfs = vec![0u8; Self::CT_SIZE];
        server_ct_obfs.copy_from_slice(&buf[..Self::CT_SIZE]);

        // chunk off the ciphertext
        let mut server_ct_obfs = vec![0u8; Self::CT_SIZE];
        server_ct_obfs.copy_from_slice(&buf[0..Self::CT_SIZE]);

        // chunk off server authentication value
        let mut server_auth =
            Authcode::<D>::clone_from_slice(&buf[Self::CT_SIZE..Self::CT_SIZE + Self::AUTH_SIZE]);
        // server_auth.copy_from_slice(
        //     &buf[Self::CT_SIZE..Self::CT_SIZE + Authcode::<D>::USIZE],
        // );

        // decode and decapsulate the secret encoded by the server
        let server_ct = <K as OKemCore>::Ciphertext::try_from_bytes(&server_ct_obfs)
            .map_err(|e| RelayHandshakeError::FailedParse)?;
        let shared_secret_1 = state
            .my_sk
            .decapsulate(&server_ct)
            .map_err(|e| RelayHandshakeError::FailedDecapsulation)?;

        let node_id = state.materials.get_identity().id;
        let mut f2 = SimpleHmac::<D>::new_from_slice(node_id.as_bytes())
            .expect("keying server f2 hmac should never fail");

        let mut f1_es = SimpleHmac::<Sha3_256>::new_from_slice(state.ephemeral_secret.as_ref())
            .expect("Keying server f1_es hmac should never fail");

        // derive the mark from the Ephemeral Secret
        let server_mark = {
            f1_es.reset();
            f1_es.update(&server_ct_obfs);
            f1_es.update(SERVER_MARK_ARG);
            f1_es.finalize_reset().into_bytes()
        };

        trace!(
            "client-{} mark?:{}",
            state.materials.session_id,
            hex::encode(server_mark)
        );

        let min_position = Server::<K, D>::SERVER_MIN_HANDSHAKE_LENGTH;

        // find mark + mac position
        let pos = match find_mac_mark::<D>(server_mark, buf, min_position, MAX_PACKET_LENGTH, true)
        {
            Some(p) => p,
            None => {
                trace!("{} didn't find mark", state.materials.session_id);
                if buf.len() > MAX_PACKET_LENGTH {
                    Err(RelayHandshakeError::BadServerHandshake)?
                }
                Err(RelayHandshakeError::EAgain)?
            }
        };

        // // TODO: should this use state.epoch_hr? Do we even need to try multiple time stamps??
        // validate he MAC
        let mut mac_found = false;
        let mut epoch_hour = String::new();
        for offset in [0_i64, -1, 1] {
            // Allow the epoch to be off by up to one hour in either direction
            trace!("server trying offset: {offset}");
            let eh = format!("{}", offset + get_epoch_hour() as i64);

            // compute the expected MAC (if the epoch hour is within the valid range)
            f1_es.reset();
            f1_es.update(&buf[..pos + D::MARK_SIZE]);
            f1_es.update(eh.as_bytes());
            f1_es.update(SERVER_MAC_ARG);
            let mac_calculated = &f1_es.finalize_reset().into_bytes()[..D::MAC_SIZE];

            // check received mac
            let mac_received = &buf[pos + D::MARK_SIZE..pos + D::MARK_SIZE + D::MAC_SIZE];
            trace!(
                "server {}-{}",
                hex::encode(mac_calculated),
                hex::encode(mac_received)
            );

            // // TODO: If an Ellyptic Curve scheme (i.e. X25519) is involved
            // // make sure that the clients mac matches and that both x25519 keys
            // // contributed (i.e. neither was 0)
            // let mut okay = computed_mac.ct_eq(&msg_mac)
            //     & ct::bool_to_choice(xy.was_contributory())
            //     & ct::bool_to_choice(xb.was_contributory());

            // make sure that the servers mac matches
            if mac_calculated.ct_eq(mac_received).into() {
                trace!("correct mac");
                epoch_hour = eh;
                mac_found = true;

                // We break here, but if this creates some kind of timing channel
                // (not sure exactly what that would be) we could reduce timing variance by
                // just evaluating all three MACs. Probably not necessary
                break;
            }
        }

        if !mac_found {
            // This could be a [`RelayHandshakeError::TagMismatch`] :shrug:
            trace!("Matching MAC not found");
            Err(RelayHandshakeError::BadServerHandshake)?
        }

        // // TODO: Not sure if this is valid
        // // server should never send any appended padding at the end.
        // if buf.len() != pos + MARK_LENGTH + MAC_LENGTH {
        //     trace!("server sent extra data");
        //     Err(RelayHandshakeError::BadServerHandshake)?
        // }

        Ok(ServerHandshakeMessage::<K, D, ServerStateIncoming>::new(
            server_ct,
            server_auth,
            ServerStateIncoming {},
        ))
    }
}
