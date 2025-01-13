use super::MessageTypes;
use crate::framing::{FrameError, Message, MessageType};

#[derive(PartialEq, Debug)]
pub enum CryptoExtension {
    Kyber,
}

#[allow(unused)]
impl CryptoExtension {
    pub(crate) fn get_offer() -> impl Message {
        KyberOfferMessage {}
    }

    pub(crate) fn create_accept() -> impl Message {
        KyberAcceptMessage {}
    }
}

#[derive(PartialEq, Debug)]
struct KyberOfferMessage {}

impl Message for KyberOfferMessage {
    type Output = ();
    fn as_pt(&self) -> MessageType {
        MessageTypes::CryptoOffer.into()
    }

    fn marshall<T: bytes::BufMut>(&self, _dst: &mut T) -> Result<(), FrameError> {
        Ok(())
    }

    fn try_parse<T: bytes::BufMut + bytes::Buf>(_buf: &mut T) -> Result<Self::Output, FrameError> {
        Ok(())
    }
}

#[derive(PartialEq, Debug)]
struct KyberAcceptMessage {}

impl Message for KyberAcceptMessage {
    type Output = ();
    fn as_pt(&self) -> MessageType {
        MessageTypes::CryptoAccept.into()
    }

    fn marshall<T: bytes::BufMut>(&self, _dst: &mut T) -> Result<(), FrameError> {
        Ok(())
    }

    fn try_parse<T: bytes::BufMut + bytes::Buf>(_buf: &mut T) -> Result<Self::Output, FrameError> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(unused)]
mod tests {
    use pqc_kyber::*;

    use crate::common::curve25519::{PublicKey, Representable};
    use crate::handshake::O5NtorSecretKey;

    type Result<T> = std::result::Result<T, Error>;

    #[derive(Debug)]
    enum Error {
        PQCError(pqc_kyber::KyberError),
        Other(Box<dyn std::error::Error>),
    }

    impl From<pqc_kyber::KyberError> for Error {
        fn from(e: pqc_kyber::KyberError) -> Self {
            Error::PQCError(e)
        }
    }

    struct Kyber1024XPublicKey {
        pub kyber1024: pqc_kyber::PublicKey,
        pub x25519: PublicKey,
    }

    impl From<&Kyber1024XIdentityKeys> for Kyber1024XPublicKey {
        fn from(value: &Kyber1024XIdentityKeys) -> Self {
            Kyber1024XPublicKey {
                x25519: value.x25519.pk.pk,
                kyber1024: value.kyber1024.public,
            }
        }
    }

    struct Kyber1024XIdentityKeys {
        pub kyber1024: pqc_kyber::Keypair,
        pub x25519: O5NtorSecretKey,
    }

    impl Kyber1024XIdentityKeys {
        fn new() -> Self {
            let mut rng = rand::thread_rng();

            Kyber1024XIdentityKeys {
                x25519: O5NtorSecretKey::getrandom(),
                kyber1024: pqc_kyber::keypair(&mut rng).expect("kyber1024 key generation failed"),
            }
        }

        fn from_random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
            Kyber1024XIdentityKeys {
                x25519: O5NtorSecretKey::getrandom(),
                kyber1024: pqc_kyber::keypair(rng).expect("kyber1024 key generation failed"),
            }
        }

        fn from_x25519<R: CryptoRng + RngCore>(keys: O5NtorSecretKey, rng: &mut R) -> Self {
            Kyber1024XIdentityKeys {
                x25519: keys,
                kyber1024: pqc_kyber::keypair(rng).expect("kyber1024 key generation failed"),
            }
        }
    }

    #[test]
    fn kyber_handshake() -> Result<()> {
        let mut rng = rand::thread_rng();

        // Generate Keypair
        let alice_secret = Representable::ephemeral_from_rng(&mut rng);
        let alice_public = PublicKey::from(&alice_secret);
        let keys_alice = keypair(&mut rng)?;
        // alice -> bob public keys
        let mut kyber1024x_pubkey = alice_public.as_bytes().to_vec();
        kyber1024x_pubkey.extend_from_slice(&keys_alice.public);

        assert_eq!(kyber1024x_pubkey.len(), 1600);

        let bob_secret = Representable::ephemeral_from_rng(&mut rng);
        let bob_public = PublicKey::from(&bob_secret);

        // Bob encapsulates a shared secret using Alice's public key
        let (ciphertext, shared_secret_bob) = encapsulate(&keys_alice.public, &mut rng)?;
        let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

        // // Alice decapsulates a shared secret using the ciphertext sent by Bob
        let shared_secret_alice = decapsulate(&ciphertext, &keys_alice.secret)?;
        let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);

        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
        assert_eq!(shared_secret_bob, shared_secret_alice);

        Ok(())
    }
}
