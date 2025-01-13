#![allow(unused)]

use tor_llcrypto::pk::ed25519::ED25519_ID_LEN;

pub use crate::common::ntor_arti::SESSION_ID_LEN;
use crate::{
    common::{drbg, x25519_elligator2::REPRESENTATIVE_LENGTH, xwing},
    framing,
    handshake::AUTHCODE_LENGTH,
};

use std::time::Duration;

pub const PUBLIC_KEY_LEN: usize = xwing::PUBKEY_LEN;

//=========================[Framing/Msgs]=====================================//

/// Maximum handshake size including padding
pub const MAX_HANDSHAKE_LENGTH: usize = 8192;

pub const SHA256_SIZE: usize = 32;
pub const MARK_LENGTH: usize = SHA256_SIZE / 2;
pub const MAC_LENGTH: usize = SHA256_SIZE / 2;

/// Minimum padding allowed in a client handshake message
pub const CLIENT_MIN_PAD_LENGTH: usize =
    (SERVER_MIN_HANDSHAKE_LENGTH + INLINE_SEED_FRAME_LENGTH) - CLIENT_MIN_HANDSHAKE_LENGTH;
pub const CLIENT_MAX_PAD_LENGTH: usize = MAX_HANDSHAKE_LENGTH - CLIENT_MIN_HANDSHAKE_LENGTH;
pub const CLIENT_MIN_HANDSHAKE_LENGTH: usize = REPRESENTATIVE_LENGTH + MARK_LENGTH + MAC_LENGTH;

pub const SERVER_MIN_PAD_LENGTH: usize = 0;
pub const SERVER_MAX_PAD_LENGTH: usize =
    MAX_HANDSHAKE_LENGTH - (SERVER_MIN_HANDSHAKE_LENGTH + INLINE_SEED_FRAME_LENGTH);
pub const SERVER_MIN_HANDSHAKE_LENGTH: usize =
    REPRESENTATIVE_LENGTH + AUTHCODE_LENGTH + MARK_LENGTH + MAC_LENGTH;

pub const INLINE_SEED_FRAME_LENGTH: usize =
    framing::FRAME_OVERHEAD + MESSAGE_OVERHEAD + SEED_MESSAGE_PAYLOAD_LENGTH;

pub const MESSAGE_OVERHEAD: usize = 2 + 1;
pub const MAX_MESSAGE_PAYLOAD_LENGTH: usize = framing::MAX_FRAME_PAYLOAD_LENGTH - MESSAGE_OVERHEAD;
pub const MAX_MESSAGE_PADDING_LENGTH: usize = MAX_MESSAGE_PAYLOAD_LENGTH;
pub const SEED_MESSAGE_PAYLOAD_LENGTH: usize = drbg::SEED_LENGTH;
pub const SEED_MESSAGE_LENGTH: usize =
    framing::LENGTH_LENGTH + MESSAGE_OVERHEAD + drbg::SEED_LENGTH + MAC_LENGTH;

pub const CONSUME_READ_SIZE: usize = framing::MAX_SEGMENT_LENGTH * 16;

//===============================[Proto]======================================//

pub const TRANSPORT_NAME: &str = "obfs4";

pub const NODE_ID_ARG: &str = "node-id";
pub const PUBLIC_KEY_ARG: &str = "public-key";
pub const PRIVATE_KEY_ARG: &str = "private-key";
pub const SEED_ARG: &str = "drbg-seed";
pub const CERT_ARG: &str = "cert";

pub const BIAS_CMD_ARG: &str = "obfs4-distBias";

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
pub const MAX_CLOSE_DELAY: usize = 60;
pub const MAX_CLOSE_DELAY_BYTES: usize = MAX_HANDSHAKE_LENGTH;

pub const SEED_LENGTH: usize = drbg::SEED_LENGTH;
pub const HEADER_LENGTH: usize = framing::FRAME_OVERHEAD + framing::MESSAGE_OVERHEAD;

pub const NODE_ID_LENGTH: usize = ED25519_ID_LEN;
pub const NODE_PUBKEY_LENGTH: usize = xwing::PUBKEY_LEN;
