//! X-Wing Hybrid Public Key Encapsulation
//!
//! todo!

use kem::{Decapsulate, Encapsulate};
use kemeleon::{Encode, OKemCore};
use rand::{CryptoRng, RngCore};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;

use crate::{Error, Result};

pub(crate) use kemeleon::EncodeError;

pub(crate) const X25519_PUBKEY_LEN: usize = 32;
pub(crate) const X25519_PRIVKEY_LEN: usize = 32;
pub(crate) const MLKEM1024_PUBKEY_LEN: usize = 1530;
pub(crate) const PUBKEY_LEN: usize = MLKEM1024_PUBKEY_LEN + X25519_PUBKEY_LEN;
pub(crate) const PRIVKEY_LEN: usize = 1;

pub struct DecapsulationKey {
    decap: x_wing::DecapsulationKey,
    kemeleon_byte: u8,
    elligator2_byte: u8,
    pub_key: EncapsulationKey,

    /// Keeping this around because we have extra randomness bytes that we need
    /// to keep track of for both elligator2 and kemeleon. -_-
    byteformat: [u8; PRIVKEY_LEN + PUBKEY_LEN],
}

#[derive(Clone, PartialEq)]
pub struct EncapsulationKey {
    encap: x_wing::EncapsulationKey,
    /// public key encoded as bytes using obfuscating encodings.
    pub_key_obfs: [u8; PUBKEY_LEN],
}

/// Generate a X-Wing key pair using the provided rng.
pub fn generate_key_pair(rng: &mut impl CryptoRngCore) -> (DecapsulationKey, EncapsulationKey) {
    let (dk, ek) = x_wing::generate_key_pair(rng);
    (dk, ek)
}

pub struct Ciphertext(x_wing::Ciphertext);

impl kem::Decapsulate<Ciphertext, SharedSecret> for DecapsulationKey {
    type Error = Error;
    fn decapsulate(
        &self,
        encapsulated_key: &Ciphertext,
    ) -> std::result::Result<SharedSecret, Self::Error> {
        // self.decap.decapsulate(encapsulated_key).into()
        todo!("out for lunch")
    }
}

impl kem::Encapsulate<Ciphertext, SharedSecret> for EncapsulationKey {
    type Error = Error;
    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> std::result::Result<(Ciphertext, SharedSecret), Self::Error> {
        todo!("out of order")
    }
}

impl DecapsulationKey {
    // TODO: THIS NEEDS TESTED
    pub fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let buf = bytes.as_ref();
        if buf.len() < 32 {
            return Err(Error::Crypto("malformed DecapsulationKey provided".into()));
        }

        let mut b = [0u8; 32];
        b.copy_from_slice(&buf[..32]);
        let privkey = x_wing::DecapsulationKey::from(b);

        todo!("not implemented: back in an hour");
        // let sk: [u8; X25519_PRIVKEY_LEN] = core::array::from_fn(|i| buf[i]);
        // let x25519 = x25519_dalek::StaticSecret::from(sk);

        // let mlkem = DecapsulationKey::from_fips_bytes(&buf[X25519_PRIVKEY_LEN..])
        //     .map_err(|e| Error::EncodeError(e.into()))?;

        // let pubkey_buf: [u8; PUBKEY_LEN] = core::array::from_fn(|i| buf[PRIVKEY_LEN + i]);
        // let pub_key = EncapsulationKey::try_from(pubkey_buf)?;

        // Ok(Self{
        //     decap,
        //     kemeleon_byte,
        //     elligator2_byte,
        //     pub_key,
        //     byteformat,
        // })
    }

    pub fn as_bytes(&self) -> [u8; PRIVKEY_LEN + PUBKEY_LEN] {
        self.byteformat.clone()
    }
}

impl core::fmt::Debug for EncapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

impl EncapsulationKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.pub_key_obfs
    }
}

impl From<&DecapsulationKey> for EncapsulationKey {
    fn from(value: &DecapsulationKey) -> Self {
        value.pub_key.clone()
    }
}

impl TryFrom<&[u8]> for DecapsulationKey {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self> {
        DecapsulationKey::try_from_bytes(value)
    }
}

impl TryFrom<&[u8]> for EncapsulationKey {
    type Error = Error;
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() < PUBKEY_LEN {
            return Err(Error::Crypto("bad publickey".into()));
        }
        let mut x25519 = [0u8; X25519_PUBKEY_LEN];
        x25519.copy_from_slice(&value[..X25519_PUBKEY_LEN]);

        let mlkem = kemeleon::EncapsulationKey::try_from_bytes(&value[X25519_PUBKEY_LEN..])
            .map_err(|e| Error::EncodeError(e.into()))?;

        let mut pub_key = [0u8; PUBKEY_LEN];
        pub_key.copy_from_slice(&value[..PUBKEY_LEN]);
        Ok(Self {
            encap,
            pub_key_obfs,
        })
    }
}

impl TryFrom<[u8; PUBKEY_LEN]> for EncapsulationKey {
    type Error = Error;
    fn try_from(value: [u8; PUBKEY_LEN]) -> Result<Self> {
        Self::try_from(&value[..])
    }
}

pub struct SharedSecret {
    shared_secret: x_wing::SharedSecret,
    x25519_raw: [u8; 32],
    mlkem: [u8; 32],
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.x25519_raw.ct_eq(&other.x25519_raw).into() && self.mlkem.ct_eq(&other.mlkem).into()
    }
}

impl SharedSecret {
    // TODO: Test this layout to make sure this works.
    // SAFETY: the type of the SharedSecret object means this should never fail
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.x25519_raw.as_ptr(), 64) }
    }
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} {}",
            hex::encode(self.x25519_raw),
            hex::encode(self.mlkem)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kemeleon::MlKem1024;

    #[test]
    fn example_lib_usage() {
        let rng = &mut rand::thread_rng();
        let (dk_alice, ek_alice) = generate_key_pair(rng);

        let (dk_bob, ek_bob) = generate_key_pair(rng);
        let (ct, bob_ss) = ek_alice
            .encapsulate(rng)
            .expect("failed to encapsulate a secret");

        let alice_ss = dk_alice.decapsulate(&ct).unwrap();
        assert_eq!(alice_ss, bob_ss);
    }

    #[test]
    /// Make sure that serializing and then deserializing each type of object works as expected.
    fn ser_de() {}

    #[test]
    fn proof_of_concept() {
        let mut rng = rand::thread_rng();

        // --- Generate Keypair (Alice) ---
        // x25519
        let alice_secret = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let alice_public = x25519_dalek::PublicKey::from(&alice_secret);
        // mlkem
        let (alice_mlkem_dk, alice_mlkem_ek) = MlKem1024::generate(&mut rng);

        // --- alice -> bob (public keys) ---
        // alice sends bob the public key for her mlkem1024 keypair with her
        // x25519 key appended to the end.
        let mut mlkem1024x_pubkey = alice_public.as_bytes().to_vec();
        mlkem1024x_pubkey.extend_from_slice(&alice_mlkem_ek.as_bytes());

        assert_eq!(mlkem1024x_pubkey.len(), 1562);

        // --- Generate Keypair (Bob) ---
        // x25519
        let bob_secret = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let bob_public = x25519_dalek::PublicKey::from(&bob_secret);

        // (Imagine) upon receiving the mlkemx25519 public key bob parses them
        // into their respective structs from bytes

        // Bob encapsulates a shared secret using Alice's public key
        let (ciphertext, shared_secret_bob) = alice_mlkem_ek.encapsulate(&mut rng).unwrap();
        let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

        // // Alice decapsulates a shared secret using the ciphertext sent by Bob
        let shared_secret_alice = alice_mlkem_dk.decapsulate(&ciphertext).unwrap();
        let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);

        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
        assert_eq!(shared_secret_bob, shared_secret_alice);
        println!(
            "{} ?= {}",
            hex::encode(shared_secret_bob),
            hex::encode(shared_secret_alice)
        );
    }
}
