//! PRNG Seed message
//!
//! Message that a server will send upon successful completion of a handshake
//! giving the client a value with which to seed the pseudo-random number generator
//! that is used for selecting padding lengths.

use crate::{common::drbg, constants::*};

pub const SEED_MESSAGE_PAYLOAD_LENGTH: usize = drbg::SEED_LENGTH;
pub const INLINE_SEED_FRAME_LENGTH: usize =
    FRAME_OVERHEAD + MESSAGE_OVERHEAD + SEED_MESSAGE_PAYLOAD_LENGTH;

pub struct PrngSeedMessage([u8; SEED_LENGTH]);
