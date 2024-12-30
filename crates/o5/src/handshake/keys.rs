use super::*;
use crate::{
    common::{
        ntor_arti::{KeyGenerator, SessionID, SessionIdentifier},
        // kdf::{Kdf, Ntor1Kdf},
    },
    constants::*,
    framing::{O5Codec, KEY_MATERIAL_LENGTH},
    Error, Result,
};

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine,
};
use hybrid_array::Array;
use kem::{Decapsulate, Encapsulate};
use kemeleon::{Encode, MlKem768, OKemCore};
use rand::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};
use tor_bytes::{EncodeResult, Readable, SecretBuf, Writeable, Writer};
use tor_llcrypto::{
    d::Shake256Reader,
    pk::ed25519::{Ed25519Identity, ED25519_ID_LEN},
};
use typenum::Unsigned;

/// Ephemeral single use session secret key type
pub struct EphemeralKey<K: OKemCore>(<K as OKemCore>::DecapsulationKey);

impl<K: OKemCore> EphemeralKey<K> {
    pub fn new(inner: K::DecapsulationKey) -> Self {
        Self(inner)
    }
}

impl<K: OKemCore> Decapsulate<K::Ciphertext, K::SharedKey> for EphemeralKey<K> {
    type Error = <K::DecapsulationKey as Decapsulate<K::Ciphertext, K::SharedKey>>::Error;

    fn decapsulate(
        &self,
        encapsulated_key: &K::Ciphertext,
    ) -> std::result::Result<K::SharedKey, Self::Error> {
        self.0.decapsulate(encapsulated_key)
    }
}

/// Public key type associated with EphemeralKey.
#[derive(Clone)]
pub struct EphemeralPub<K: OKemCore>(<K as OKemCore>::EncapsulationKey);

impl<K: OKemCore> EphemeralPub<K> {
    pub fn new(inner: K::EncapsulationKey) -> Self {
        Self(inner)
    }
}

impl<K: OKemCore> Encapsulate<K::Ciphertext, K::SharedKey> for EphemeralPub<K> {
    type Error = <K::EncapsulationKey as Encapsulate<K::Ciphertext, K::SharedKey>>::Error;

    fn encapsulate(
        &self,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> std::result::Result<(K::Ciphertext, K::SharedKey), Self::Error> {
        self.0.encapsulate(rng)
    }
}

impl<K: OKemCore> Encode for EphemeralPub<K> {
    type Error = <K::EncapsulationKey as Encode>::Error;
    type EncodedSize = EkSize<K>;

    fn as_bytes(&self) -> ml_kem::array::Array<u8, Self::EncodedSize> {
        self.0.as_bytes()
    }

    fn try_from_bytes<B: AsRef<[u8]>>(buf: B) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self(<K::EncapsulationKey as Encode>::try_from_bytes(buf)?))
    }
}

impl<K: OKemCore> Readable for EphemeralPub<K> {
    fn take_from(_b: &mut tor_bytes::Reader<'_>) -> tor_bytes::Result<Self> {
        todo!("Session Public Key `EphemeralPub<K>` Reader needs implemented");
    }
}

impl<K: OKemCore> Writeable for EphemeralPub<K> {
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        todo!("Session Public Key `EphemeralPub<K>` Writer needs implemented");
    }
}

/// Key information about a relay used for the ntor v3 handshake.
///
/// Contains a single curve25519 ntor onion key, and the relay's ed25519
/// identity.
#[derive(PartialEq)]
pub struct IdentityPublicKey<K: OKemCore> {
    /// The relay's identity.
    pub(crate) id: Ed25519Identity,
    /// The relay's onion key.
    pub(crate) ek: <K as OKemCore>::EncapsulationKey,
}

impl<K: OKemCore> Clone for IdentityPublicKey<K> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            ek: <K as OKemCore>::EncapsulationKey::from(self.ek.clone()),
        }
    }
}

impl<K: OKemCore> core::fmt::Debug for IdentityPublicKey<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdentityPublicKey")
            .field("id", &self.id)
            .field("pk", &hex::encode(&self.ek.as_bytes()[0..16]))
            .finish()
    }
}

impl<K: OKemCore> From<&IdentitySecretKey<K>> for IdentityPublicKey<K> {
    fn from(value: &IdentitySecretKey<K>) -> Self {
        value.pk.clone()
    }
}

impl<K: OKemCore> IdentityPublicKey<K> {
    const CERT_LENGTH: usize = EkSize::<K>::USIZE + ED25519_ID_LEN;
    const CERT_SUFFIX: &'static str = "==";

    /// Construct a new IdentityPublicKey from its components.
    #[allow(unused)]
    pub(crate) fn new(ek_bytes: impl AsRef<[u8]>, id: [u8; NODE_ID_LENGTH]) -> Result<Self> {
        let ek = K::EncapsulationKey::try_from_bytes(ek_bytes)
            .map_err(|_| Error::other("failed to parse Identity Key"))?;
        Ok(Self { ek, id: id.into() })
    }

    pub fn try_from_bytes(buf: impl AsRef<[u8]>) -> std::result::Result<Self, Error> {
        let arr = buf.as_ref();
        if arr.len() < Self::CERT_LENGTH {
            return Err(Error::other(
                "provided identity key is improperly formatted -- too short",
            ));
        }
        let id: [u8; NODE_ID_LENGTH] = arr[..ED25519_ID_LEN].try_into()?;
        let ek =
            Array::<u8, <<K as OKemCore>::EncapsulationKey as Encode>::EncodedSize>::from_fn(|i| {
                arr[ED25519_ID_LEN + i]
            });
        IdentityPublicKey::new(ek, id)
    }
}

impl<K: OKemCore> std::str::FromStr for IdentityPublicKey<K> {
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
        IdentityPublicKey::new(&decoded[NODE_ID_LENGTH..], id)
    }
}

#[allow(clippy::to_string_trait_impl)]
impl<K: OKemCore> std::string::ToString for IdentityPublicKey<K> {
    fn to_string(&self) -> String {
        let mut s = Vec::from(self.id.as_bytes());
        s.extend(self.ek.as_bytes());
        STANDARD_NO_PAD.encode(s)
    }
}

impl<K: OKemCore> Readable for IdentityPublicKey<K> {
    fn take_from(_b: &mut tor_bytes::Reader<'_>) -> tor_bytes::Result<Self> {
        todo!("IdentityPublicKey Reader needs implemented");
    }
}

/// Secret key information used by a relay for the ntor v3 handshake.
pub struct IdentitySecretKey<K: OKemCore> {
    /// The relay's public key information
    pub(crate) pk: IdentityPublicKey<K>,
    /// The secret onion key.
    pub(super) sk: <K as OKemCore>::DecapsulationKey,
}

impl<K: OKemCore> IdentitySecretKey<K> {
    /// Construct a new IdentitySecretKey from its components.
    #[allow(unused)]
    pub(crate) fn new(sk: <K as OKemCore>::DecapsulationKey, id: Ed25519Identity) -> Self {
        Self {
            pk: IdentityPublicKey {
                id,
                ek: K::encapsulation_key(&sk),
            },
            sk,
        }
    }

    pub fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let buf = bytes.as_ref();
        if buf.len() < NODE_ID_LENGTH {
            return Err(Error::other("bad station identity cert provided"));
        }

        let mut id = [0u8; NODE_ID_LENGTH];
        id.copy_from_slice(&buf[..NODE_ID_LENGTH]);
        let sk = K::DecapsulationKey::try_from_bytes(&buf[NODE_ID_LENGTH..])
            .map_err(|_| Error::other("failed to parse decapsulation key"))?;
        Ok(Self::new(sk, id.into()))
    }

    /// Generate a key using the given `rng`, suitable for testing.
    pub(crate) fn random_from_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut id = [0_u8; NODE_ID_LENGTH];
        // Random bytes will work for testing, but aren't necessarily actually a valid id.
        rng.fill_bytes(&mut id);
        // let sk = DecapsulationKey::random_from_rng(rng);
        let (dk, ek) = K::generate(rng);
        Self::new(dk, id.into())
    }

    /// Checks whether `id` and `pk` match this secret key.
    ///
    /// Used to perform a constant-time secret key lookup.
    pub(crate) fn matches(
        &self,
        id: Ed25519Identity,
        ek: <K as OKemCore>::EncapsulationKey,
    ) -> Choice {
        id.as_bytes().ct_eq(self.pk.id.as_bytes()) & ek.as_bytes().ct_eq(&self.pk.ek.as_bytes()[..])
    }
}

impl<K: OKemCore> TryFrom<&[u8]> for IdentitySecretKey<K> {
    type Error = Error;
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::try_from_bytes(value)
    }
}

// impl<K:OKemCore> Into<<K as OKemCore>::EncapsulationKey> for &IdentityPublicKey<K> {
//     fn into(self) -> <K as OKemCore>::EncapsulationKey {
//         self.ek.clone()
//     }
// }
//
// impl<K:OKemCore> Into<<K as OKemCore>::EncapsulationKey> for &IdentitySecretKey<K> {
//     fn into(self) -> <K as OKemCore>::EncapsulationKey {
//         self.pk.ek.clone()
//     }
// }

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

impl From<NtorV3KeyGenerator> for O5Codec {
    fn from(val: NtorV3KeyGenerator) -> Self {
        val.codec
    }
}

impl NtorV3KeyGen for NtorV3KeyGenerator {}

impl NtorV3KeyGenerator {
    pub(crate) fn new<R: Role>(mut reader: NtorV3XofReader) -> Self {
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
