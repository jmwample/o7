#![allow(unused)] // TODO: Remove this. nothing unused should stay
// #![deny(missing_docs)]

use kemeleon::{Encode, EncodingSize, KemeleonByteArraySize, OKemCore};
use ml_kem::{Ciphertext, MlKem768Params};
use tor_llcrypto::pk::ed25519::ED25519_ID_LEN;
use typenum::Unsigned;

pub use crate::common::ntor_arti::SESSION_ID_LEN;
use crate::{
    common::{drbg, x25519_elligator2::REPRESENTATIVE_LENGTH},
    framing,
};

use std::{marker::PhantomData, time::Duration};

//=========================[Packets / Messages]=================================//

pub(crate) type EkSize<K> = <<K as OKemCore>::EncapsulationKey as Encode>::EncodedSize;
pub(crate) type CtSize<K> = <<K as OKemCore>::Ciphertext as Encode>::EncodedSize;

pub const SHA256_SIZE: usize = 32;
pub const MARK_LENGTH: usize = SHA256_SIZE;
pub const MAC_LENGTH: usize = SHA256_SIZE;

/// Maximum handshake size including padding
pub const MAX_HANDSHAKE_LENGTH: usize = 16_384;
const MAX_HANDSHAKE_PAD_LENGTH: usize = 8192;
const MIN_HANDSHAKE_PAD_LENGTH: usize = 0;

/// Minimum padding allowed in a client handshake message
pub const CLIENT_MIN_PAD_LENGTH: usize = MIN_HANDSHAKE_PAD_LENGTH + CLIENT_MIN_HANDSHAKE_LENGTH;
/// Maximum padding included in a client handshake message
pub const CLIENT_MAX_PAD_LENGTH: usize = MAX_HANDSHAKE_PAD_LENGTH - CLIENT_MIN_HANDSHAKE_LENGTH;

/// Minimum possible valid client handshake length.
// pub const CLIENT_MIN_HANDSHAKE_LENGTH: usize = REPRESENTATIVE_LENGTH + MARK_LENGTH + MAC_LENGTH;
pub const CLIENT_MIN_HANDSHAKE_LENGTH: usize = REPRESENTATIVE_LENGTH + MARK_LENGTH + MAC_LENGTH;

/// Minimum padding allowed in a server handshake message
pub const SERVER_MIN_PAD_LENGTH: usize = 0;
/// Maximum padding included in a server handshake message
pub const SERVER_MAX_PAD_LENGTH: usize =
    MAX_HANDSHAKE_LENGTH; // TODO // - (SERVER_MIN_HANDSHAKE_LENGTH + INLINE_SEED_FRAME_LENGTH);

// /// Minimum possible sever handshake length // TODO
// pub const SERVER_MIN_HANDSHAKE_LENGTH: usize =
//     REPRESENTATIVE_LENGTH + AUTHCODE_LENGTH + MARK_LENGTH + MAC_LENGTH;

//===============================[Framing]=====================================//

pub const INLINE_SEED_FRAME_LENGTH: usize =
    framing::FRAME_OVERHEAD + MESSAGE_OVERHEAD + SEED_MESSAGE_PAYLOAD_LENGTH;

pub const MESSAGE_OVERHEAD: usize = 2 + 1;
pub const MAX_MESSAGE_PAYLOAD_LENGTH: usize = framing::MAX_FRAME_PAYLOAD_LENGTH - MESSAGE_OVERHEAD;
pub const MAX_MESSAGE_PADDING_LENGTH: usize = MAX_MESSAGE_PAYLOAD_LENGTH;
pub const SEED_MESSAGE_PAYLOAD_LENGTH: usize = drbg::SEED_LENGTH;
pub const SEED_MESSAGE_LENGTH: usize =
    framing::LENGTH_LENGTH + MESSAGE_OVERHEAD + drbg::SEED_LENGTH + MAC_LENGTH;

pub const CONSUME_READ_SIZE: usize = framing::MAX_SEGMENT_LENGTH * 16;

pub const NODE_ID_LENGTH: usize = ED25519_ID_LEN;
pub const SEED_LENGTH: usize = drbg::SEED_LENGTH;
pub const HEADER_LENGTH: usize = framing::FRAME_OVERHEAD + framing::MESSAGE_OVERHEAD;

//===============================[Transport]===================================//

pub const CLIENT_MARK_ARG: &[u8] = b":05-mc";
pub const SERVER_MARK_ARG: &[u8] = b":05-ms";
pub const CLIENT_MAC_ARG:  &[u8] = b":05-mac_c";
pub const SERVER_MAC_ARG:  &[u8] = b":o5-mac_s";
pub const SERVER_AUTH_ARG: &[u8] = b":o5-sever_mac";
pub const KEY_EXTRACT_ARG: &[u8] = b":o5-key_extract";
pub const KEY_DERIVE_ARG:  &[u8] = b":o5-derive_key";

// argument / parameter names
pub const NODE_ID_ARG:     &str = "node-id";
pub const PUBLIC_KEY_ARG:  &str = "public-key";
pub const PRIVATE_KEY_ARG: &str = "private-key";
pub const SEED_ARG:        &str = "drbg-seed";
pub const BIAS_CMD_ARG:    &str = "o5-distBias";
pub const CERT_ARG:        &str = "cert";

// default timeouts
pub const REPLAY_TTL: Duration = Duration::from_secs(60);
#[cfg(test)]
pub const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
pub const SERVER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(not(test))]
pub const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(not(test))]
pub const SERVER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

pub const MAX_IPT_DELAY: usize = 100;

// failed handshake close conditions
pub const MAX_CLOSE_DELAY: usize = 60;
pub const MAX_CLOSE_DELAY_BYTES: usize = MAX_HANDSHAKE_LENGTH;
