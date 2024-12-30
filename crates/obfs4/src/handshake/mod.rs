//! Implements the ntor handshake, as used in modern Tor.

use crate::{
    common::{
        ct,
        kdf::{Kdf, Ntor1Kdf},
        ntor_arti::{
            AuxDataReply, ClientHandshake, KeyGenerator, RelayHandshakeError, RelayHandshakeResult,
            ServerHandshake,
        },
        x25519_elligator2::{EphemeralSecret, Keys, PublicKey, SharedSecret, StaticSecret},
    },
    constants::*,
    framing::{Obfs4Codec, KEY_MATERIAL_LENGTH},
    Error, Result, Server,
};

use std::borrow::Borrow;

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use bytes::BytesMut;
use digest::Mac;
use hmac::Hmac;
use ptrs::warn;
use subtle::ConstantTimeEq;
use tor_bytes::{EncodeResult, SecretBuf, Writer};
use tor_error::into_internal;
use tor_llcrypto::d::Sha256;
use tor_llcrypto::pk::rsa::RsaIdentity;

#[cfg(test)]
use rand::{CryptoRng, RngCore};

mod handshake_client;
mod handshake_server;
mod utils;

// TODO: this is a special tool that will help us later.
pub(crate) use utils::*;

pub(crate) use handshake_client::HandshakeMaterials as CHSMaterials;
#[cfg(test)]
pub(crate) use handshake_client::{
    client_handshake2_no_auth_check_obfs4, client_handshake_obfs4_no_keygen,
};
use handshake_client::{client_handshake2_obfs4, client_handshake_obfs4, NtorHandshakeState};
pub(crate) use handshake_server::HandshakeMaterials as SHSMaterials;

pub(crate) const PROTO_ID: &[u8; 24] = b"ntor-curve25519-sha256-1";
pub(crate) const T_MAC: &[u8; 28] = b"ntor-curve25519-sha256-1:mac";
pub(crate) const T_VERIFY: &[u8; 35] = b"ntor-curve25519-sha256-1:key_verify";
pub(crate) const T_KEY: &[u8; 36] = b"ntor-curve25519-sha256-1:key_extract";
pub(crate) const M_EXPAND: &[u8; 35] = b"ntor-curve25519-sha256-1:key_expand";

/// Struct containing associated function for the obfs4 Ntor handshake.
pub(crate) struct Obfs4NtorHandshake;

impl ClientHandshake for Obfs4NtorHandshake {
    type KeyType = CHSMaterials;
    type StateType = NtorHandshakeState;
    type KeyGen = NtorHkdfKeyGenerator;
    type ClientAuxData = ();
    type ServerAuxData = BytesMut;

    fn client1<M: Borrow<()>>(
        key: &Self::KeyType,
        _client_aux_data: &M,
    ) -> Result<(Self::StateType, Vec<u8>)> {
        client_handshake_obfs4(key)
    }

    fn client2<T: AsRef<[u8]>>(
        state: Self::StateType,
        msg: T,
    ) -> Result<(Self::ServerAuxData, Self::KeyGen)> {
        let (keygen, remainder) = client_handshake2_obfs4(msg, &state)?;
        Ok((BytesMut::from(&remainder[..]), keygen))
    }
}

impl ServerHandshake for Server {
    type KeyType = SHSMaterials;
    type KeyGen = NtorHkdfKeyGenerator;
    type ClientAuxData = ();
    type ServerAuxData = ();

    fn server<REPLY: AuxDataReply<Self>, T: AsRef<[u8]>>(
        &self,
        reply_fn: &mut REPLY,
        key: &[Self::KeyType],
        msg: T,
    ) -> RelayHandshakeResult<(Self::KeyGen, Vec<u8>)> {
        reply_fn
            .reply(&())
            .ok_or(RelayHandshakeError::BadClientHandshake)?;

        if key.is_empty() {
            return Err(RelayHandshakeError::MissingKey);
        }

        if key.len() > 1 {
            warn!("Multiple keys provided, but only the first key will be used");
        }

        let shs_materials = key[0].clone();

        self.server_handshake_obfs4(msg, shs_materials)
    }
}

/// Key information about a relay used for the ntor v3 handshake.
///
/// Contains a single curve25519 ntor onion key, and the relay's ed25519
/// identity.
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Obfs4NtorPublicKey {
    /// Public RSA identity fingerprint for the relay; used in authentication
    /// calculation.
    pub(crate) id: RsaIdentity,
    /// The Bridge's identity key.
    pub(crate) pk: PublicKey,
}

impl Obfs4NtorPublicKey {
    const CERT_LENGTH: usize = NODE_ID_LENGTH + NODE_PUBKEY_LENGTH;
    const CERT_SUFFIX: &'static str = "==";
    /// Construct a new Obfs4NtorPublicKey from its components.
    #[allow(unused)]
    pub(crate) fn new(pk: [u8; NODE_PUBKEY_LENGTH], id: [u8; NODE_ID_LENGTH]) -> Self {
        Self {
            pk: pk.into(),
            id: id.into(),
        }
    }
}

impl std::str::FromStr for Obfs4NtorPublicKey {
    type Err = Error;
    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        let mut cert = String::from(s);
        cert.push_str(Self::CERT_SUFFIX);
        let decoded = STANDARD
            .decode(cert.as_bytes())
            .map_err(|e| format!("failed to decode cert: {e}"))?;
        if decoded.len() != Self::CERT_LENGTH {
            return Err(format!("cert length {} is invalid", decoded.len()).into());
        }
        let id: [u8; NODE_ID_LENGTH] = decoded[..NODE_ID_LENGTH].try_into().unwrap();
        let pk: [u8; NODE_PUBKEY_LENGTH] = decoded[NODE_ID_LENGTH..].try_into().unwrap();
        Ok(Obfs4NtorPublicKey::new(pk, id))
    }
}

#[allow(clippy::to_string_trait_impl)]
impl std::string::ToString for Obfs4NtorPublicKey {
    fn to_string(&self) -> String {
        let mut s = Vec::from(self.id.as_bytes());
        s.extend(self.pk.as_bytes());
        STANDARD_NO_PAD.encode(s)
    }
}

/// Secret key information used by a relay for the ntor v3 handshake.
#[derive(Clone)]
pub(crate) struct Obfs4NtorSecretKey {
    /// The relay's public key information
    pub(crate) pk: Obfs4NtorPublicKey,
    /// The secret onion key.
    pub(crate) sk: StaticSecret,
}

impl Obfs4NtorSecretKey {
    /// Construct a new Obfs4NtorSecretKey from its components.
    #[allow(unused)]
    pub(crate) fn new(sk: StaticSecret, id: RsaIdentity) -> Self {
        let pk = PublicKey::from(&sk);
        Self {
            pk: Obfs4NtorPublicKey { id, pk },
            sk,
        }
    }

    /// Construct a new ['Obfs4NtorSecretKey'] from a CSPRNG.
    pub(crate) fn getrandom() -> Self {
        let sk = Keys::random_static();
        let mut id = [0_u8; NODE_ID_LENGTH];
        getrandom::getrandom(&mut id).expect("internal randomness error");
        Self::new(sk, RsaIdentity::from(id))
    }

    /// Generate a key using the given `rng`, suitable for testing.
    #[cfg(test)]
    pub(crate) fn generate_for_test<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut id = [0_u8; 20];
        // Random bytes will work for testing, but aren't necessarily actually a valid id.
        rng.fill_bytes(&mut id);

        let sk = Keys::static_from_rng(rng);

        let pk = Obfs4NtorPublicKey {
            pk: (&sk).into(),
            id: id.into(),
        };
        Self { pk, sk }
    }
}

/// KeyGenerator for use with ntor circuit handshake.
pub(crate) struct NtorHkdfKeyGenerator {
    /// Secret key information derived from the handshake, used as input
    /// to HKDF
    seed: SecretBuf,
    codec: Obfs4Codec,
    session_id: [u8; SESSION_ID_LEN],
}

impl NtorHkdfKeyGenerator {
    /// Create a new key generator to expand a given seed
    pub(crate) fn new(seed: SecretBuf, is_client: bool) -> Self {
        // use the seed value to bootstrap Read / Write crypto codec.
        let okm = Self::kdf(&seed[..], KEY_MATERIAL_LENGTH * 2 + SESSION_ID_LEN)
            .expect("bug: failed to derive key material from seed");

        let ekm: [u8; KEY_MATERIAL_LENGTH] = okm[KEY_MATERIAL_LENGTH..KEY_MATERIAL_LENGTH * 2]
            .try_into()
            .unwrap();
        let dkm: [u8; KEY_MATERIAL_LENGTH] = okm[..KEY_MATERIAL_LENGTH].try_into().unwrap();

        let session_id = okm[KEY_MATERIAL_LENGTH * 2..].try_into().unwrap();

        // server ekm == client dkm and vice-versa
        let codec = match is_client {
            false => Obfs4Codec::new(ekm, dkm),
            true => Obfs4Codec::new(dkm, ekm),
        };

        NtorHkdfKeyGenerator {
            seed,
            codec,
            session_id,
        }
    }

    fn kdf(seed: impl AsRef<[u8]>, keylen: usize) -> Result<SecretBuf> {
        Ntor1Kdf::new(&T_KEY[..], &M_EXPAND[..]).derive(seed.as_ref(), keylen)
    }
}

impl KeyGenerator for NtorHkdfKeyGenerator {
    fn expand(self, keylen: usize) -> Result<SecretBuf> {
        let ntor1_key = &T_KEY[..];
        let ntor1_expand = &M_EXPAND[..];
        Ntor1Kdf::new(ntor1_key, ntor1_expand).derive(&self.seed[..], keylen)
    }
}

// /// Alias for an HMAC output, used to validate correctness of a handshake.
// pub(crate) type Authcode = [u8; 32];
// pub(crate) const AUTHCODE_LENGTH: usize = 32;

// /// helper: compute a key generator and an authentication code from a set
// /// of ntor parameters.
// ///
// /// These parameter names are as described in tor-spec.txt
// fn ntor_derive(
//     xy: &SharedSecret,
//     xb: &SharedSecret,
//     server_pk: &Obfs4NtorPublicKey,
//     x: &PublicKey,
//     y: &PublicKey,
// ) -> EncodeResult<(SecretBuf, Authcode)> {
//     // ) -> EncodeResult<(NtorHkdfKeyGenerator, Authcode)> {
//     let server_string = &b"Server"[..];

//     // obfs4 uses a different order than Ntor V1 and accidentally writes the
//     // server's identity public key bytes twice.
//     let mut suffix = SecretBuf::new();
//     suffix.write(&server_pk.pk.as_bytes())?; // b
//     suffix.write(&server_pk.pk.as_bytes())?; // b
//     suffix.write(x.as_bytes())?; // x
//     suffix.write(y.as_bytes())?; // y
//     suffix.write(PROTO_ID)?; // PROTOID
//     suffix.write(&server_pk.id)?; // ID

//     // secret_input = EXP(X,y) | EXP(X,b)   OR    = EXP(Y,x) | EXP(B,x)
//     // ^ these are the equivalent x25519 shared secrets concatenated
//     //
//     // message = (secret_input) | b | b | x | y | PROTOID | ID
//     let mut message = SecretBuf::new();
//     message.write(xy.as_bytes())?; // EXP(X,y)
//     message.write(xb.as_bytes())?; // EXP(X,b)
//     message.write(&suffix[..])?; // b | b | x | y | PROTOID | ID

//     // verify = HMAC_SHA256(msg, T_VERIFY)
//     let verify = {
//         let mut m = Hmac::<Sha256>::new_from_slice(T_VERIFY).expect("Hmac allows keys of any size");
//         m.update(&message[..]);
//         m.finalize()
//     };

//     // auth_input = verify | (suffix) | "Server"
//     // auth_input = verify | b | b | y | x | PROTOID | ID | "Server"
//     //
//     // Again obfs4 uses all of the same fields (with the servers identity public
//     // key duplicated), but in a different order than Ntor V1.
//     let mut auth_input = Vec::new();
//     auth_input.write_and_consume(verify)?; // verify
//     auth_input.write(&suffix[..])?; // b | b | x | y | PROTOID | ID
//     auth_input.write(server_string)?; // "Server"

//     // auth = HMAC_SHA256(auth_input, T_MAC)
//     let auth_mac = {
//         let mut m = Hmac::<Sha256>::new_from_slice(T_MAC).expect("Hmac allows keys of any size");
//         m.update(&auth_input[..]);
//         m.finalize()
//     };
//     let auth: [u8; 32] = auth_mac.into_bytes()[..].try_into().unwrap();

//     // key_seed = HMAC_SHA256(message, T_KEY)
//     let key_seed_bytes = {
//         let mut m = Hmac::<Sha256>::new_from_slice(T_KEY).expect("Hmac allows keys of any size");
//         m.update(&message[..]);
//         m.finalize()
//     };
//     let mut key_seed = SecretBuf::new();
//     key_seed.write_and_consume(key_seed_bytes)?;

//     Ok((key_seed, auth))
// }

/// Obfs4 helper trait to ensure that a returned key generator can be used
/// to create a usable codec and retrieve a session id.
pub trait Obfs4Keygen: KeyGenerator + Into<Obfs4Codec> {
    fn session_id(&mut self) -> [u8; SESSION_ID_LEN];
}

impl Obfs4Keygen for NtorHkdfKeyGenerator {
    fn session_id(&mut self) -> [u8; SESSION_ID_LEN] {
        self.session_id
    }
}

impl From<NtorHkdfKeyGenerator> for Obfs4Codec {
    fn from(keygen: NtorHkdfKeyGenerator) -> Self {
        keygen.codec
    }
}

#[cfg(test)]
mod integration;
