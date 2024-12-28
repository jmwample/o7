use std::marker::PhantomData;

use crate::{
    common::{
        ct,
        ntor_arti::{
            ClientHandshake, ClientHandshakeComplete, ClientHandshakeMaterials, KeyGenerator,
        },
        utils::get_epoch_hour,
    },
    constants::*,
    framing::{handshake::ClientHandshakeMessage, ClientStateOutgoing},
    handshake::{keys::*, *},
    Error, Result,
};

use bytes::BytesMut;
use digest::CtOutput;
use hmac::{Hmac, Mac};
use kem::{Decapsulate, Encapsulate};
use kemeleon::{Encode, OKemCore};
// use cipher::KeyIvInit;
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
use zeroize::Zeroizing;

/// Client state for the o5 (ntor v3) handshake.
///
/// The client needs to hold this state between when it sends its part
/// of the handshake and when it receives the relay's reply.
pub(crate) struct HandshakeState<K: OKemCore> {
    /// The temporary curve25519 secret (x) that we've generated for
    /// this handshake.
    // We'd like to EphemeralSecret here, but we can't since we need
    // to use it twice.
    my_sk: EphemeralKey<K>,

    /// handshake materials
    pub(crate) materials: HandshakeMaterials<K>,

    /// the computed hour at which the initial portion of the handshake was sent.
    epoch_hr: String,

    /// The shared secret generated as F2(node_id, encapsulation_key)
    ephemeral_secret: Zeroizing<[u8; ENC_KEY_LEN]>,
}

impl<K: OKemCore> HandshakeState<K> {
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
    pub(crate) pad_len: usize,
    pub(crate) session_id: String,
    pub(crate) aux_data: Vec<NtorV3Extension>,
}

impl<K: OKemCore> HandshakeMaterials<K> {
    pub(crate) fn new(node_pubkey: &IdentityPublicKey<K>, session_id: String) -> Self {
        HandshakeMaterials {
            node_pubkey: node_pubkey.clone(),
            session_id,
            pad_len: rand::thread_rng().gen_range(CLIENT_MIN_PAD_LENGTH..CLIENT_MAX_PAD_LENGTH),
            aux_data: vec![],
        }
    }

    pub fn with_early_data(mut self, data: impl AsRef<[NtorV3Extension]>) -> Self {
        self.aux_data = data.as_ref().to_vec();
        self
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
pub(crate) struct NtorV3Client<K: OKemCore> {
    _okem: PhantomData<K>,
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

impl<K: OKemCore> ClientHandshake for NtorV3Client<K> {
    type StateType = HandshakeState<K>;
    type HandshakeMaterials = HandshakeMaterials<K>;
    type HsOutput = HsComplete;

    /// Generate a new client onionskin for a relay with a given onion key.
    /// If any `extensions` are provided, encode them into to the onionskin.
    ///
    /// On success, return a state object that will be used to complete the handshake, along
    /// with the message to send.
    fn client1(hs_materials: Self::HandshakeMaterials) -> Result<(Self::StateType, Vec<u8>)> {
        let mut rng = rand::thread_rng();

        Ok(client_handshake_ntor_v3::<K>(&mut rng, hs_materials)
            .map_err(into_internal!("Can't encode ntor3 client handshake."))?)
    }

    /// Handle an onionskin from a relay, and produce a key generator.
    ///
    /// The state object must match the one that was used to make the
    /// client onionskin that the server is replying to.
    fn client2<T: AsRef<[u8]>>(state: &mut Self::StateType, msg: T) -> Result<Self::HsOutput> {
        let (message, xof_reader) = client_handshake_ntor_v3_part2::<K>(state, msg.as_ref())?;
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

/// Client-side Ntor version 3 handshake, part one.
///
/// Given a secure `rng`, a relay's public key, a secret message to send, generate a new handshake
/// state and a message to send to the relay.
pub(crate) fn client_handshake_ntor_v3<K: OKemCore>(
    rng: &mut impl CryptoRngCore,
    materials: HandshakeMaterials<K>,
) -> EncodeResult<(HandshakeState<K>, Vec<u8>)> {
    let keys = K::generate(rng);
    client_handshake_ntor_v3_no_keygen::<K>(rng, keys, materials)
}

/// As `client_handshake_ntor_v3`, but don't generate an ephemeral DH
/// key: instead take that key an arguments `my_sk`.
///
/// (DK, EK , EK1) <-- OKEM.KGen()
pub(crate) fn client_handshake_ntor_v3_no_keygen<K: OKemCore>(
    rng: &mut impl CryptoRngCore,
    keys: (K::DecapsulationKey, K::EncapsulationKey),
    materials: HandshakeMaterials<K>,
) -> EncodeResult<(HandshakeState<K>, Vec<u8>)> {
    let ephemeral_ek = EphemeralPub::new(keys.1);
    let hs_materials = ClientStateOutgoing {
        hs_materials: materials.clone(),
    };
    let mut client_msg =
        ClientHandshakeMessage::<K, ClientStateOutgoing<K>>::new(ephemeral_ek, hs_materials);

    // ------------ [ Perform Handshake and Serialize Packet ] ------------ //

    let mut buf = BytesMut::with_capacity(MAX_HANDSHAKE_LENGTH);
    let ephemeral_secret = client_msg.marshall(rng, &mut buf)?;

    let state = HandshakeState {
        materials,
        my_sk: keys::EphemeralKey::new(keys.0),
        ephemeral_secret,
        epoch_hr: client_msg.get_epoch_hr(),
    };

    Ok((state, buf.to_vec()))
}

/// Finalize the handshake on the client side.
///
/// Called after we've received a message from the relay: try to
/// complete the handshake and verify its correctness.
///
/// On success, return the server's reply to our original encrypted message,
/// and an `XofReader` to use in generating circuit keys.
pub(crate) fn client_handshake_ntor_v3_part2<K: OKemCore>(
    state: &HandshakeState<K>,
    relay_handshake: &[u8],
) -> Result<(Vec<u8>, NtorV3XofReader)> {
    todo!("client handshake part 2");

    // let mut reader = Reader::from_slice(relay_handshake);
    // let y_pk: EphemeralPub::<K> = reader
    //     .extract()
    //     .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;
    // let auth: DigestVal = reader
    //     .extract()
    //     .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;
    // let encrypted_msg = reader.into_rest();
    // let my_public = EphemeralPub::<K>::from(&state.my_sk);

    // // TODO: Some of this code is duplicated from the server handshake code!  It
    // // would be better to factor it out.
    // let yx = state.my_sk.diffie_hellman(&y_pk);
    // let secret_input = {
    //     let mut si = SecretBuf::new();
    //     si.write(&yx)
    //         .and_then(|_| si.write(&state.shared_secret.as_bytes()))
    //         .and_then(|_| si.write(&state.node_id()))
    //         .and_then(|_| si.write(&state.node_pubkey().as_bytes()))
    //         .and_then(|_| si.write(&my_public.as_bytes()))
    //         .and_then(|_| si.write(&y_pk.as_bytes()))
    //         .and_then(|_| si.write(PROTOID))
    //         .and_then(|_| si.write(&Encap(verification)))
    //         .map_err(into_internal!("error encoding ntor3 secret_input"))?;
    //     si
    // };
    // let ntor_key_seed = h_key_seed(&secret_input);
    // let verify = h_verify(&secret_input);

    // let computed_auth: DigestVal = {
    //     use digest::Digest;
    //     let mut auth = DigestWriter(Sha3_256::default());
    //     auth.write(&T_AUTH)
    //         .and_then(|_| auth.write(&verify))
    //         .and_then(|_| auth.write(&state.node_id()))
    //         .and_then(|_| auth.write(&state.node_pubkey().as_bytes()))
    //         .and_then(|_| auth.write(&y_pk.as_bytes()))
    //         .and_then(|_| auth.write(&my_public.as_bytes()))
    //         .and_then(|_| auth.write(&state.msg_mac))
    //         .and_then(|_| auth.write(&Encap(encrypted_msg)))
    //         .and_then(|_| auth.write(PROTOID))
    //         .and_then(|_| auth.write(&b"Server"[..]))
    //         .map_err(into_internal!("error encoding ntor3 authentication input"))?;
    //     auth.take().finalize().into()
    // };

    // let okay = computed_auth.ct_eq(&auth)
    //     & ct::bool_to_choice(yx.was_contributory())
    //     & ct::bool_to_choice(state.shared_secret.was_contributory());

    // let (enc_key, keystream) = {
    //     use digest::{ExtendableOutput, XofReader};
    //     let mut xof = DigestWriter(Shake256::default());
    //     xof.write(&T_FINAL)
    //         .and_then(|_| xof.write(&ntor_key_seed))
    //         .map_err(into_internal!("error encoding ntor3 xof input"))?;
    //     let mut r = xof.take().finalize_xof();
    //     let mut enc_key = Zeroizing::new([0_u8; ENC_KEY_LEN]);
    //     r.read(&mut enc_key[..]);
    //     (enc_key, r)
    // };
    // let server_reply = decrypt(&enc_key, encrypted_msg);

    // if okay.into() {
    //     Ok((server_reply, NtorV3XofReader::new(keystream)))
    // } else {
    //     Err(Error::BadCircHandshakeAuth)
    // }
}
