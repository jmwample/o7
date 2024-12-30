#![doc = include_str!("../README.md")]
// #![warn(missing_docs)]
#![allow(unused)]

use digest::FixedOutputReset;

pub mod client;
pub mod common;
pub mod extensions;
pub mod framing;
pub mod proto;
pub mod server;
pub use client::{Client, ClientBuilder};
pub use server::{Server, ServerBuilder};


#[rustfmt::skip]
pub(crate) mod constants;
pub(crate) mod handshake;
pub(crate) mod sessions;
pub(crate) mod traits;
pub use traits::Digest;

#[cfg(test)]
mod testing;

mod pt;
pub use pt::{Transport, O5PT};

mod error;
pub use error::{Error, Result};

macro_rules! transport_name {
    () => {
        "o5"
    };
}
pub(crate) use transport_name;

macro_rules! type_name {
    ($t:ty) => {
        "{<$t>::NAME}"
    };
}
pub(crate) use type_name;

pub const TRANSPORT_NAME: &str = transport_name!();

#[cfg(test)]
pub(crate) mod test_utils;

#[cfg(any(debug_assertions, test))]
pub mod dev {
    /// Pre-generated / shared key for use while running in debug mode.
    pub const DEV_PRIV_KEY: &[u8; 32] = b"0123456789abcdeffedcba9876543210";

    /// Client obfs4 arguments based on pre-generated dev key `DEV_PRIV_KEY`.
    pub const CLIENT_ARGS: &str =
        "cert=AAAAAAAAAAAAAAAAAAAAAAAAAADTSFvsGKxNFPBcGdOCBSgpEtJInG9zCYZezBPVBuBWag";

    /// Server obfs4 arguments based on pre-generated dev key `DEV_PRIV_KEY`.
    pub const SERVER_ARGS: &str = "drbg-seed=0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f;node-id=0000000000000000000000000000000000000000;private-key=3031323334353637383961626364656666656463626139383736353433323130";
}

/*
#[cfg(test)]
#[allow(unused)]
mod ml_kem_tests {
    use anyhow::{anyhow, Context, Result};
    use ml_kem::*;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    struct Kyber1024XKeypair {}

    impl Kyber1024XKeypair {
        fn new() -> Result<Self> {
            todo!()
        }
    }

    #[test]
    fn it_works() -> Result<()> {
        let mut rng = rand::thread_rng();

        // --- Generate Keypair (Alice) ---
        // x25519
        let alice_secret = EphemeralSecret::random_from_rng(&mut rng);
        let alice_public = PublicKey::from(&alice_secret);
        // kyber
        let (alice_kyber_dk, alice_kyber_ek) = MlKem1024::generate(&mut rng);

        // --- alice -> bob (public keys) ---
        // alice sends bob the public key for her kyber1024 keypair with her
        // x25519 key appended to the end.
        let mut kyber1024x_pubkey = alice_public.as_bytes().to_vec();
        kyber1024x_pubkey.extend_from_slice(&alice_kyber_ek.as_bytes());

        assert_eq!(kyber1024x_pubkey.len(), 1600);

        // --- Generate Keypair (Bob) ---
        // x25519
        let bob_secret = EphemeralSecret::random_from_rng(&mut rng);
        let bob_public = PublicKey::from(&bob_secret);

        // (Imagine) upon receiving the kyberx25519 public key bob parses them
        // into their respective structs from bytes

        // Bob encapsulates a shared secret using Alice's public key
        let (ciphertext, shared_secret_bob) = alice_kyber_ek.encapsulate(&mut rng).unwrap();
        let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

        // // Alice decapsulates a shared secret using the ciphertext sent by Bob
        let shared_secret_alice = alice_kyber_dk.decapsulate(&ciphertext).unwrap();
        let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);

        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
        assert_eq!(shared_secret_bob, shared_secret_alice);
        println!(
            "{} ?= {}",
            hex::encode(shared_secret_bob),
            hex::encode(shared_secret_alice)
        );

        Ok(())
    }
}
*/
