#![allow(unused)] // TODO: Remove this. nothing unused should stay
// #![deny(missing_docs)]

use kemeleon::{Encode, EncodingSize, KemeleonByteArraySize, OKemCore};
use ml_kem::{Ciphertext, MlKem768Params};
use tor_llcrypto::pk::ed25519::ED25519_ID_LEN;
use typenum::Unsigned;
use digest::OutputSizeUser;

pub use crate::common::ntor_arti::SESSION_ID_LEN;
use crate::{
    common::{drbg, x25519_elligator2::REPRESENTATIVE_LENGTH},
    framing,
};

use std::{marker::PhantomData, time::Duration};

//=============================[ Framing / Messages =============================//

pub(crate) use framing::FRAME_OVERHEAD;
pub const MESSAGE_OVERHEAD: usize = 2 + 1;
pub const MAX_MESSAGE_PAYLOAD_LENGTH: usize = framing::MAX_FRAME_PAYLOAD_LENGTH - MESSAGE_OVERHEAD;
pub const MAX_MESSAGE_PADDING_LENGTH: usize = MAX_MESSAGE_PAYLOAD_LENGTH;

pub const CONSUME_READ_SIZE: usize = framing::MAX_SEGMENT_LENGTH * 16;

pub const NODE_ID_LENGTH: usize = ED25519_ID_LEN;
pub const SEED_LENGTH: usize = drbg::SEED_LENGTH;
pub const HEADER_LENGTH: usize = framing::FRAME_OVERHEAD + framing::MESSAGE_OVERHEAD;

//=================================[ Transport ]=================================//

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
pub const CERT_ARG:        &str = "cert";

//============================[ Traffic Fingerprint ]============================//

/// Maximum handshake size including padding
pub const MAX_PACKET_LENGTH: usize = 16_384;
pub(crate) const MAX_PAD_LENGTH: usize = 8192;
pub(crate) const MIN_PAD_LENGTH: usize = 0;

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
pub const MAX_CLOSE_DELAY_BYTES: usize = MAX_PACKET_LENGTH;
