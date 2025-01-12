//! Implements the ntor v3 key exchange, as described in proposal 332.
//!
//! The main difference between the ntor v3r handshake and the
//! original ntor handshake is that this this one allows each party to
//! encrypt data (without forward secrecy) after it sends the first
//! message.

use crate::{common::ntor_arti::ClientHandshakeComplete, Digest};

use cipher::{KeyIvInit as _, StreamCipher as _};
use digest::{
    generic_array::{ArrayLength, GenericArray},
    Digest as _, ExtendableOutput as _, OutputSizeUser, XofReader as _,
};
use kemeleon::{Encode, OKemCore};
use tor_bytes::{EncodeResult, Writeable, Writer};
use tor_llcrypto::cipher::aes::Aes256Ctr;
use tor_llcrypto::d::{Sha3_256, Shake256};
use zeroize::{Zeroize, Zeroizing};

mod keys;
pub(crate) use keys::NtorV3KeyGenerator;
use keys::NtorV3XofReader;
pub use keys::{EphemeralKey, EphemeralPub, IdentityPublicKey, IdentitySecretKey, NtorV3KeyGen};

/// Super trait to be used where we require a distinction between client and server roles.
pub trait Role {
    fn is_client() -> bool;
}

pub struct ClientRole {}
impl Role for ClientRole {
    fn is_client() -> bool {
        true
    }
}

pub struct ServerRole {}
impl Role for ServerRole {
    fn is_client() -> bool {
        false
    }
}

mod client;
pub(crate) use client::{
    HandshakeMaterials as CHSMaterials, HsComplete as ClientHsComplete, NtorV3Client,
};

mod server;
pub(crate) use server::{HandshakeMaterials as SHSMaterials, ServerHandshake};

/// The size of an encryption key in bytes.
pub const ENC_KEY_LEN: usize = 32;
/// The size of a MAC key in bytes.
pub const MAC_KEY_LEN: usize = 32;
/// The size of a digest output in bytes.
pub const DIGEST_LEN: usize = 32;
/// The length of a MAC output in bytes.
pub const MAC_LEN: usize = 32;
/// The length of a node identity in bytes.
pub const ID_LEN: usize = 32;

/// The output of the digest, as an array.
type DigestVal = [u8; DIGEST_LEN];
/// The output of the MAC.
type MessageMac = [u8; MAC_LEN];
/// A key for message authentication codes.
type MacKey = [u8; MAC_KEY_LEN];

/// Alias for an HMAC output
type HmacOutput<D> = digest::generic_array::GenericArray<u8, <D as OutputSizeUser>::OutputSize>;

/// HMAC code used to authenticate the server.
pub(crate) type Authcode<D> = HmacOutput<D>;

/// A key for symmetric encryption and decryption.
pub(crate) type SessionSharedSecret<D> = Zeroizing<HmacOutput<D>>;

/// Secret derived using an HMAC, used as the intermediary secret during a handshake.
pub(crate) type HandshakeEphemeralSecret<D> = Zeroizing<HmacOutput<D>>;

// /// An encapsulated value for passing as input to a MAC, digest, or
// /// KDF algorithm.
// ///
// /// This corresponds to the ENCAP() function in proposal 332.
// struct Encap<'a>(&'a [u8]);

// impl Writeable for Encap<'_> {
//     fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
//         b.write_u64(self.0.len() as u64);
//         b.write(self.0)
//     }
// }

// impl<'a> Encap<'a> {
//     /// Return the length of the underlying data in bytes.
//     fn len(&self) -> usize {
//         self.0.len()
//     }
//     /// Return the underlying data
//     fn data(&self) -> &'a [u8] {
//         self.0
//     }
// }

/// Helper to define a set of tweak values as instances of `Encap`.
macro_rules! define_tweaks {
    {
        $(#[$pid_meta:meta])*
        PROTOID = $protoid:expr;
        $( $(#[$meta:meta])* $name:ident <= $suffix:expr ; )*
    } => {
        $(#[$pid_meta])*
        const PROTOID: &'static [u8] = $protoid.as_bytes();
        $(
            $(#[$meta])*
            const $name: &[u8] = concat!($protoid, ":", $suffix).as_bytes();
        )*
    }
}

pub(crate) const T_KEY: &[u8] = b"ntor-curve25519-sha256-1:key_extract";

define_tweaks! {
    /// Protocol ID: concatenated with other things in the protocol to
    /// prevent hash confusion.
    PROTOID =  "ntor3-curve25519-sha3_256-1";

    /// Message MAC tweak: used to compute the MAC of an encrypted client
    /// message.
    // in obfs4 -> b"ntor-curve25519-sha256-1:mac"
    T_MSGMAC <= "msg_mac";
    /// Message KDF tweak: used when deriving keys for encrypting and MACing
    /// client message.
    T_MSGKDF <= "kdf_phase1";
    /// Key seeding tweak: used to derive final KDF input from secret_input.
    T_KEY_SEED <= "key_seed";
    /// Verifying tweak: used to derive 'verify' value from secret_input.
    // in obfs4 ->  b"ntor-curve25519-sha256-1:key_verify"
    T_VERIFY <= "verify";
    /// Final KDF tweak: used to derive keys for encrypting relay message
    /// and for the actual tor circuit.
    T_FINAL <= "kdf_final";
    /// Authentication tweak: used to derive the final authentication
    /// value for the handshake.
    T_AUTH <= "auth_final";
    /// Key Expansion Tweak: obfs4 tweak used for expanding seed into key
    M_EXPAND <= "key_expand";
}

// /// Compute a tweaked hash.
// fn hash(t: &Encap<'_>, data: &[u8]) -> DigestVal {
//     let mut d = Sha3_256::new();
//     d.update((t.len() as u64).to_be_bytes());
//     d.update(t.data());
//     d.update(data);
//     d.finalize().into()
// }

/// Perform a symmetric encryption operation and return the encrypted data.
///
/// (This isn't safe to do more than once with the same key, but we never
/// do that in this protocol.)
pub(crate) fn encrypt<D: Digest>(key: &SessionSharedSecret<D>, m: &[u8]) -> Vec<u8> {
    let mut d = m.to_vec();
    let zero_iv = Default::default();
    let mut k = [0u8; 32];
    k[..32].copy_from_slice(&<SessionSharedSecret<D> as AsRef<[u8]>>::as_ref(key)[..32]);
    let mut cipher = Aes256Ctr::new((&k).into(), &zero_iv);
    cipher.apply_keystream(&mut d);
    d
}

/// Perform a symmetric decryption operation and return the encrypted data.
pub(crate) fn decrypt<D: Digest>(key: &SessionSharedSecret<D>, m: &[u8]) -> Vec<u8>
where
    generic_array::GenericArray<u8, <D as OutputSizeUser>::OutputSize>: Zeroize,
    <D as OutputSizeUser>::OutputSize: ArrayLength<u8>,
{
    encrypt::<D>(key, m)
}

// /// Hash tweaked with T_KEY_SEED
// fn h_key_seed(d: &[u8]) -> DigestVal {
//     hash(&T_KEY_SEED, d)
// }
// /// Hash tweaked with T_VERIFY
// fn h_verify(d: &[u8]) -> DigestVal {
//     hash(&T_VERIFY, d)
// }

/// Trait for an object that handle and incoming client message and
/// return a server's reply.
///
/// This is implemented for `FnMut(&[u8]) -> Option<Vec<u8>>` automatically.
pub(crate) trait MsgReply {
    /// Given a message received from a client, parse it and decide
    /// how (and whether) to reply.
    ///
    /// Return None if the handshake should fail.
    fn reply(&mut self, msg: &[u8]) -> Option<Vec<u8>>;
}

impl<F> MsgReply for F
where
    F: FnMut(&[u8]) -> Option<Vec<u8>>,
{
    fn reply(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        self(msg)
    }
}

#[cfg(test)]
#[allow(non_snake_case)] // to enable variable names matching the spec.
#[allow(clippy::many_single_char_names)] // ibid
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use crate::common::ntor_arti::{
        ClientHandshake, ClientHandshakeComplete, KeyGenerator, ServerHandshake as _,
    };
    use crate::constants::{NODE_ID_LENGTH, SEED_LENGTH};
    use crate::handshake::server::ServerHandshake;
    use crate::test_utils::init_subscriber;
    use crate::Server;

    use super::*;
    use crate::handshake::IdentitySecretKey;
    use crate::test_utils::test_keys::KEYS;

    use bytes::BytesMut;
    use hex::FromHex;
    use hex_literal::hex;
    use kemeleon::{MlKem768, OKemCore};
    use rand::thread_rng;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_cell::relaycell::extend::NtorV3Extension;
    use tor_llcrypto::pk::ed25519::Ed25519Identity;

    type O5Client = client::NtorV3Client<MlKem768, Sha3_256>;
    type Decap<T> = <T as OKemCore>::DecapsulationKey;

    #[test]
    fn test_ntor3_roundtrip() {
        init_subscriber();
        let mut rng = rand::thread_rng();
        let relay_private = IdentitySecretKey::random_from_rng(&mut testing_rng());

        let client_message = &b"Hello. I am a client. Let's be friends!"[..];
        let relay_message = &b"Greetings, client. I am a robot. Beep boop."[..];
        let materials = CHSMaterials::new(&relay_private.pk, "fake_session_id-1".into());

        let mut c_handshake = BytesMut::new();
        let c_state =
            O5Client::client_handshake_ntor_v3(&mut rng, materials, &mut c_handshake).unwrap();

        struct Rep(Vec<u8>, Vec<u8>);
        impl MsgReply for Rep {
            fn reply(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
                self.0 = msg.to_vec();
                Some(self.1.clone())
            }
        }
        let mut rep = Rep(Vec::new(), relay_message.to_vec());

        let server = Server::<MlKem768, Sha3_256>::new(relay_private);
        let shs_materials = SHSMaterials::new("test_server_000".into(), [0u8; SEED_LENGTH]);
        let server_hs = ServerHandshake::new(server.clone(), shs_materials);

        let (s_handshake, mut s_keygen) = server_hs
            .handshake_ntor_v3(&mut rng, &mut rep, &c_handshake)
            .unwrap();

        let mut shs_msg = BytesMut::new();
        s_handshake
            .marshall(&mut rng, &mut shs_msg)
            .expect("failed to serialize server handshake");

        let (s_msg, mut c_keygen) =
            O5Client::client_handshake_ntor_v3_part2(&shs_msg, &c_state).unwrap();

        assert_eq!(rep.0[..], client_message[..]);
        assert_eq!(s_msg[..], relay_message[..]);
        let mut s_keys = [0_u8; 100];
        let mut c_keys = [0_u8; 1000];
        s_keygen.read(&mut s_keys);
        c_keygen.read(&mut c_keys);
        assert_eq!(s_keys[..], c_keys[..100]);
    }

    // Same as previous test, but use the higher-level APIs instead.
    #[test]
    fn test_ntor3_roundtrip_highlevel() {
        init_subscriber();
        let relay_private = IdentitySecretKey::random_from_rng(&mut testing_rng());

        let materials = CHSMaterials::new(&relay_private.pk, "fake_session_id-1".into());
        let mut c_handshake = BytesMut::new();
        let mut c_state = O5Client::client1(materials, &mut c_handshake).unwrap();

        let mut rep = |_: &[NtorV3Extension]| Some(vec![]);

        let server = Server::<MlKem768, Sha3_256>::new_from_random(&mut thread_rng());
        let shs_materials = SHSMaterials {
            len_seed: [0u8; SEED_LENGTH],
            session_id: "roundtrip_test_serverside".into(),
        };

        let mut s_handshake = BytesMut::new();
        let s_keygen = ServerHandshake::new(server.clone(), shs_materials)
            .server(&mut rep, &c_handshake, &mut s_handshake)
            .unwrap();

        let hs_complete = NtorV3Client::client2(&mut c_state, s_handshake).unwrap();

        let extensions = hs_complete.extensions();
        let mut keygen = hs_complete.keygen();
        assert!(extensions.is_empty());
        let c_keys = keygen.expand(1000).unwrap();
        let s_keys = s_keygen.expand(100).unwrap();
        assert_eq!(s_keys[..], c_keys[..100]);
    }

    // Same as previous test, but encode some congestion control extensions.
    #[test]
    fn test_ntor3_roundtrip_highlevel_cc() {
        init_subscriber();
        let relay_private = IdentitySecretKey::random_from_rng(&mut testing_rng());

        let client_exts = vec![NtorV3Extension::RequestCongestionControl];
        let reply_exts = vec![NtorV3Extension::AckCongestionControl { sendme_inc: 42 }];
        let materials = CHSMaterials::new(&relay_private.pk, "client_session_1".into())
            .with_early_data([NtorV3Extension::RequestCongestionControl]);

        let mut c_handshake = BytesMut::new();
        let mut c_state = O5Client::client1(materials, &mut c_handshake).unwrap();

        let mut rep = |msg: &[NtorV3Extension]| -> Option<Vec<NtorV3Extension>> {
            assert_eq!(msg, client_exts);
            Some(reply_exts.clone())
        };

        let shs_materials = SHSMaterials {
            len_seed: [0u8; SEED_LENGTH],
            session_id: "roundtrip_test_serverside".into(),
        };
        let server = Server::<MlKem768, Sha3_256>::new_from_random(&mut thread_rng());
        let mut s_handshake = BytesMut::new();
        let s_keygen = ServerHandshake::new(server.clone(), shs_materials)
            .server(&mut rep, &c_handshake, &mut s_handshake)
            .unwrap();

        let hs_complete = NtorV3Client::client2(&mut c_state, s_handshake).unwrap();

        let extensions = hs_complete.extensions();
        let mut keygen = hs_complete.keygen();
        assert_eq!(extensions, &reply_exts);
        let c_keys = keygen.expand(1000).unwrap();
        let s_keys = s_keygen.expand(100).unwrap();
        assert_eq!(s_keys[..], c_keys[..100]);
    }

    #[test]
    fn test_ntor3_testvec() {
        let mut rng = rand::thread_rng();
        let b = hex::decode(KEYS[0].b).expect("failed to unhex b");
        let id = <[u8; NODE_ID_LENGTH]>::from_hex(KEYS[0].id).unwrap();
        let x = hex::decode(KEYS[0].x).expect("failed to unhex x");
        let y = hex::decode(KEYS[0].y).expect("failed to unhex y");
        let b = Decap::<MlKem768>::try_from_bytes(&b[..]).expect("failed to parse b");
        let B = b.encapsulation_key(); // K::EncapsulationKey::from(&b);
        let x = Decap::<MlKem768>::try_from_bytes(&x[..]).expect("failed_to parse x");
        let X = x.encapsulation_key();
        let y = Decap::<MlKem768>::try_from_bytes(&y[..]).expect("failed to parse y");

        let client_message = hex!("68656c6c6f20776f726c64");
        let server_message = hex!("486f6c61204d756e646f");

        let relay_private = IdentitySecretKey::<MlKem768>::new(b, id.into());
        let relay_public = IdentityPublicKey::<MlKem768>::from(&relay_private); // { pk: B, id };

        let mut chs_materials = CHSMaterials::new(&relay_public, "0000000000000000".into());
        let mut client_handshake = BytesMut::new();
        let state = O5Client::client_handshake_ntor_v3_no_keygen(
            &mut rng,
            (x, X),
            chs_materials,
            &mut client_handshake,
        )
        .unwrap();

        assert_eq!(client_handshake[..], hex!("9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2f8307a2bc1870b00b828bb74dbb8fd88e632a6375ab3bcd1ae706aaa8b6cdd1d252fe9ae91264c91d4ecb8501f79d0387e34ad8ca0f7c995184f7d11d5da4f463bebd9151fd3b47c180abc9e044d53565f04d82bbb3bebed3d06cea65db8be9c72b68cd461942088502f67")[..]);

        struct Replier(Vec<u8>, Vec<u8>, bool);
        impl MsgReply for Replier {
            fn reply(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
                assert_eq!(msg, &self.0);
                self.2 = true;
                Some(self.1.clone())
            }
        }
        let mut rep = Replier(client_message.to_vec(), server_message.to_vec(), false);
        let materials = SHSMaterials {
            session_id: "testing".into(),
            len_seed: [0u8; SEED_LENGTH],
        };

        let server = Server::<MlKem768, Sha3_256>::new(relay_private);
        let server_hs = ServerHandshake::new(server.clone(), materials);
        let (server_handshake, mut server_keygen) = server_hs
            .handshake_ntor_v3_no_keygen(&mut rng, &mut rep, &client_handshake)
            .unwrap();
        assert!(rep.2);

        let mut shs_msg = BytesMut::new();
        server_handshake
            .marshall(&mut rng, &mut shs_msg)
            .expect("failed to serialize server handshake");

        // This will fail
        assert_eq!(shs_msg[..], hex!("4bf4814326fdab45ad5184f5518bd7fae25dc59374062698201a50a22954246d2fc5f8773ca824542bc6cf6f57c7c29bbf4e5476461ab130c5b18ab0a91276651202c3e1e87c0d32054c")[..]);

        let (server_msg_received, mut client_keygen) =
            O5Client::client_handshake_ntor_v3_part2(&shs_msg, &state).unwrap();
        assert_eq!(&server_msg_received, &server_message);

        let (c_keys, s_keys) = {
            let mut c = [0_u8; 256];
            let mut s = [0_u8; 256];
            client_keygen.read(&mut c);
            server_keygen.read(&mut s);
            (c, s)
        };
        assert_eq!(c_keys, s_keys);
        assert_eq!(c_keys[..], hex!("9c19b631fd94ed86a817e01f6c80b0743a43f5faebd39cfaa8b00fa8bcc65c3bfeaa403d91acbd68a821bf6ee8504602b094a254392a07737d5662768c7a9fb1b2814bb34780eaee6e867c773e28c212ead563e98a1cd5d5b4576f5ee61c59bde025ff2851bb19b721421694f263818e3531e43a9e4e3e2c661e2ad547d8984caa28ebecd3e4525452299be26b9185a20a90ce1eac20a91f2832d731b54502b09749b5a2a2949292f8cfcbeffb790c7790ed935a9d251e7e336148ea83b063a5618fcff674a44581585fd22077ca0e52c59a24347a38d1a1ceebddbf238541f226b8f88d0fb9c07a1bcd2ea764bbbb5dacdaf5312a14c0b9e4f06309b0333b4a")[..]);
    }
}

// /// Helper: compute the encryption key and mac_key for the client's
// /// encrypted message.
// ///
// /// Takes as inputs `xb` (the shared secret derived from
// /// diffie-hellman as Bx or Xb), the relay's public key information,
// /// the client's public key (B), and the shared verification string.
// fn kdf_msgkdf<K: OKemCore>(
//     xb: &<K as OKemCore>::SharedKey,
//     relay_public: &IdentityPublicKey<K>,
//     client_public: &EphemeralPub<K>,
//     verification: &[u8],
// ) -> EncodeResult<(SessionSharedSecret, DigestWriter<Sha3_256>)> {
//     // secret_input_phase1 = Bx | ID | X | B | PROTOID | ENCAP(VER)
//     // phase1_keys = KDF_msgkdf(secret_input_phase1)
//     // (ENC_K1, MAC_K1) = PARTITION(phase1_keys, ENC_KEY_LEN, MAC_KEY_LEN
//     let mut msg_kdf = DigestWriter(Shake256::default());
//     msg_kdf.write(&T_MSGKDF)?;
//     msg_kdf.write(&xb.as_bytes()[..])?;
//     msg_kdf.write(&relay_public.id)?;
//     msg_kdf.write(&client_public.as_bytes()[..])?;
//     msg_kdf.write(&relay_public.ek.as_bytes()[..])?;
//     msg_kdf.write(PROTOID)?;
//     msg_kdf.write(&Encap(verification))?;
//     let mut r = msg_kdf.take().finalize_xof();
//     let mut enc_key = Zeroizing::new([0; ENC_KEY_LEN]);
//     let mut mac_key = Zeroizing::new([0; MAC_KEY_LEN]);

//     r.read(&mut enc_key[..]);
//     r.read(&mut mac_key[..]);
//     let mut mac = DigestWriter(Sha3_256::default());
//     {
//         mac.write(&T_MSGMAC)?;
//         mac.write(&Encap(&mac_key[..]))?;
//         mac.write(&relay_public.id)?;
//         mac.write(&relay_public.ek.as_bytes()[..])?;
//         mac.write(&client_public.as_bytes()[..])?;
//     }

//     Ok((enc_key, mac))
// }
