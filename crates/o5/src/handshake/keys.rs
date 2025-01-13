use super::*;
use crate::{
    common::{
        ntor_arti::{KeyGenerator, SessionID, SessionIdentifier},
        // kdf::{Kdf, Ntor1Kdf},
        xwing::{self, Ciphertext, DecapsulationKey, EncapsulationKey, SharedSecret},
    },
    constants::*,
    framing::{O5Codec, KEY_MATERIAL_LENGTH},
    Error, Result,
};

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine,
};
use kem::Encapsulate;
use subtle::{Choice, ConstantTimeEq};
use tor_bytes::{Readable, SecretBuf};
use tor_llcrypto::{d::Shake256Reader, pk::ed25519::Ed25519Identity};

use rand::{CryptoRng, RngCore};

/// Key information about a relay used for the ntor v3 handshake.
///
/// Contains a single curve25519 ntor onion key, and the relay's ed25519
/// identity.
#[derive(Clone, Debug, PartialEq)]
pub struct IdentityPublicKey {
    /// The relay's identity.
    pub(crate) id: Ed25519Identity,
    /// The relay's onion key.
    pub(crate) ek: EncapsulationKey,
}

impl From<&IdentitySecretKey> for IdentityPublicKey {
    fn from(value: &IdentitySecretKey) -> Self {
        value.pk.clone()
    }
}

impl IdentityPublicKey {
    const CERT_LENGTH: usize = xwing::PUBKEY_LEN;
    const CERT_SUFFIX: &'static str = "==";
    /// Construct a new IdentityPublicKey from its components.
    #[allow(unused)]
    pub(crate) fn new(ek_bytes: [u8; xwing::PUBKEY_LEN], id: [u8; NODE_ID_LENGTH]) -> Result<Self> {
        Ok(Self {
            ek: ek_bytes.try_into()?,
            id: id.into(),
        })
    }
}

impl std::str::FromStr for IdentityPublicKey {
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
        let id: [u8; NODE_ID_LENGTH] = decoded[..NODE_ID_LENGTH].try_into()?;
        let ek: [u8; NODE_PUBKEY_LENGTH] = decoded[NODE_ID_LENGTH..].try_into()?;
        IdentityPublicKey::new(ek, id)
    }
}

#[allow(clippy::to_string_trait_impl)]
impl std::string::ToString for IdentityPublicKey {
    fn to_string(&self) -> String {
        let mut s = Vec::from(self.id.as_bytes());
        s.extend(self.ek.as_bytes());
        STANDARD_NO_PAD.encode(s)
    }
}

impl Readable for IdentityPublicKey {
    fn take_from(_b: &mut tor_bytes::Reader<'_>) -> tor_bytes::Result<Self> {
        todo!("IdentityPublicKey Reader needs implemented");
    }
}

/// Secret key information used by a relay for the ntor v3 handshake.
pub struct IdentitySecretKey {
    /// The relay's public key information
    pub(crate) pk: IdentityPublicKey,
    /// The secret onion key.
    pub(super) sk: DecapsulationKey,
}

impl IdentitySecretKey {
    /// Construct a new IdentitySecretKey from its components.
    #[allow(unused)]
    pub(crate) fn new(sk: DecapsulationKey, id: Ed25519Identity) -> Self {
        Self {
            pk: IdentityPublicKey {
                id,
                ek: EncapsulationKey::from(&sk),
            },
            sk,
        }
    }

    pub fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let buf = bytes.as_ref();
        if buf.len() < xwing::PRIVKEY_LEN + NODE_ID_LENGTH {
            return Err(Error::new("bad station identity cert provided"));
        }

        let mut id = [0u8; NODE_ID_LENGTH];
        id.copy_from_slice(&buf[..NODE_ID_LENGTH]);
        let sk = DecapsulationKey::try_from_bytes(&buf[NODE_ID_LENGTH..])?;
        Ok(Self::new(sk, id.into()))
    }

    /// Generate a key using the given `rng`, suitable for testing.
    pub(crate) fn random_from_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut id = [0_u8; NODE_ID_LENGTH];
        // Random bytes will work for testing, but aren't necessarily actually a valid id.
        rng.fill_bytes(&mut id);
        // let sk = DecapsulationKey::random_from_rng(rng);
        let (dk, ek) = xwing::generate_key_pair(rng);
        Self::new(dk, id.into())
    }

    /// Checks whether `id` and `pk` match this secret key.
    ///
    /// Used to perform a constant-time secret key lookup.
    pub(crate) fn matches(&self, id: Ed25519Identity, ek: EncapsulationKey) -> Choice {
        id.as_bytes().ct_eq(self.pk.id.as_bytes()) & ek.as_bytes().ct_eq(self.pk.ek.as_bytes())
    }
}

impl TryFrom<&[u8]> for IdentitySecretKey {
    type Error = Error;
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::try_from_bytes(value)
    }
}

impl Into<xwing::EncapsulationKey> for &IdentityPublicKey {
    fn into(self) -> xwing::EncapsulationKey {
        self.ek.clone()
    }
}

impl Into<xwing::EncapsulationKey> for &IdentitySecretKey {
    fn into(self) -> xwing::EncapsulationKey {
        self.pk.ek.clone()
    }
}

pub trait NtorV3KeyGen: KeyGenerator + SessionIdentifier + Into<O5Codec> {}

/// Opaque wrapper type for NtorV3's hash reader.
#[derive(Clone)]
pub(crate) struct NtorV3XofReader(Shake256Reader);

impl NtorV3XofReader {
    pub(crate) fn new(reader: Shake256Reader) -> Self {
        Self(reader)
    }
}

impl digest::XofReader for NtorV3XofReader {
    fn read(&mut self, buffer: &mut [u8]) {
        self.0.read(buffer);
    }
}

/// A key generator returned from an ntor v3 handshake.
pub struct NtorV3KeyGenerator {
    /// The underlying `digest::XofReader`.
    reader: NtorV3XofReader,
    session_id: SessionID,
    codec: O5Codec,
}

impl KeyGenerator for NtorV3KeyGenerator {
    fn expand(mut self, keylen: usize) -> Result<SecretBuf> {
        let mut ret: SecretBuf = vec![0; keylen].into();
        self.reader.read(ret.as_mut());
        Ok(ret)
    }
}

impl NtorV3KeyGen for NtorV3KeyGenerator {}

impl NtorV3KeyGenerator {
    pub fn new<R: Role>(mut reader: NtorV3XofReader) -> Self {
        // let okm = Self::kdf(&seed[..], KEY_MATERIAL_LENGTH * 2 + SESSION_ID_LEN)
        //     .expect("bug: failed to derive key material from seed");

        // use the seed value to bootstrap Read / Write crypto codec and session ID.
        let mut ekm = [0u8; KEY_MATERIAL_LENGTH];
        reader.read(&mut ekm);
        let mut dkm = [0u8; KEY_MATERIAL_LENGTH];
        reader.read(&mut dkm);

        let mut id = [0u8; SESSION_ID_LEN];
        reader.read(&mut id);

        // server ekm == client dkm and vice-versa
        let codec = match R::is_client() {
            false => O5Codec::new(ekm, dkm),
            true => O5Codec::new(dkm, ekm),
        };

        Self {
            reader,
            codec,
            session_id: id.into(),
        }
    }
}

impl SessionIdentifier for NtorV3KeyGenerator {
    type ID = SessionID;
    fn session_id(&mut self) -> Self::ID {
        self.session_id
    }
}

impl KeyGenerator for NtorV3XofReader {
    fn expand(mut self, keylen: usize) -> Result<SecretBuf> {
        // let ntor1_key = &T_KEY_SEED[..];
        // let ntor1_expand = &M_EXPAND[..];
        // Ntor1Kdf::new(ntor1_key, ntor1_expand).derive(&self.seed[..], keylen)
        let mut ret: SecretBuf = vec![0; keylen].into();
        self.0.read(ret.as_mut());
        Ok(ret)
    }
}

impl<K: NtorV3KeyGen> From<K> for O5Codec {
    fn from(value: K) -> Self {
        value.into()
    }
}

/// Alias for an HMAC output, used to validate correctness of a handshake.
pub(crate) type Authcode = [u8; 32];
pub(crate) const AUTHCODE_LENGTH: usize = 32;

// /// helper: compute a key generator and an authentication code from a set
// /// of ntor parameters.
// ///
// /// These parameter names are as described in tor-spec.txt
// fn ntor_derive(
//     xy: &SharedSecret,
//     xb: &SharedSecret,
//     server_pk: &IdentityPublicKey,
//     x: &PublicKey,
//     y: &PublicKey,
// ) -> EncodeResult<(SecretBuf, Authcode)> {
//     // ) -> EncodeResult<(NtorHkdfKeyGenerator, Authcode)> {
//     let server_string = &b"Server"[..];
//
//     // obfs4 uses a different order than Ntor V1 and accidentally writes the
//     // server's identity public key bytes twice.
//     let mut suffix = SecretBuf::new();
//     suffix.write(&server_pk.pk.as_bytes())?; // b
//     suffix.write(&server_pk.pk.as_bytes())?; // b
//     suffix.write(x.as_bytes())?; // x
//     suffix.write(y.as_bytes())?; // y
//     suffix.write(PROTOID)?; // PROTOID
//     suffix.write(&server_pk.id)?; // ID
//
//     // secret_input = EXP(X,y) | EXP(X,b)   OR    = EXP(Y,x) | EXP(B,x)
//     // ^ these are the equivalent x25519 shared secrets concatenated
//     //
//     // message = (secret_input) | b | b | x | y | PROTOID | ID
//     let mut message = SecretBuf::new();
//     message.write(xy.as_bytes())?; // EXP(X,y)
//     message.write(xb.as_bytes())?; // EXP(X,b)
//     message.write(&suffix[..])?; // b | b | x | y | PROTOID | ID
//
//     // verify = HMAC_SHA256(msg, T_VERIFY)
//     let verify = {
//         let mut m = Hmac::<Sha256>::new_from_slice(T_VERIFY).expect("Hmac allows keys of any size");
//         m.update(&message[..]);
//         m.finalize()
//     };
//
//     // auth_input = verify | (suffix) | "Server"
//     // auth_input = verify | b | b | y | x | PROTOID | ID | "Server"
//     //
//     // Again obfs4 uses all of the same fields (with the servers identity public
//     // key duplicated), but in a different order than Ntor V1.
//     let mut auth_input = Vec::new();
//     auth_input.write_and_consume(verify)?; // verify
//     auth_input.write(&suffix[..])?; // b | b | x | y | PROTOID | ID
//     auth_input.write(server_string)?; // "Server"
//
//     // auth = HMAC_SHA256(auth_input, T_MAC)
//     let auth_mac = {
//         let mut m = Hmac::<Sha256>::new_from_slice(T_MAC).expect("Hmac allows keys of any size");
//         m.update(&auth_input[..]);
//         m.finalize()
//     };
//     let auth: [u8; 32] = auth_mac.into_bytes()[..].try_into().unwrap();
//
//     // key_seed = HMAC_SHA256(message, T_KEY)
//     let key_seed_bytes = {
//         let mut m = Hmac::<Sha256>::new_from_slice(T_KEY).expect("Hmac allows keys of any size");
//         m.update(&message[..]);
//         m.finalize()
//     };
//     let mut key_seed = SecretBuf::new();
//     key_seed.write_and_consume(key_seed_bytes)?;
//
//     Ok((key_seed, auth))
// }
