use crate::Error;

mod base;
pub use base::*;

mod messages_v1;
pub use messages_v1::{MessageTypes, Messages};

pub mod extensions;

pub(crate) mod handshake;
pub use handshake::*;

/// Error indicating that a message decoded, or a message provided for
/// encoding is of an inappropriate type for the context.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq)]

pub enum InvalidMessage {
    #[error("msg header contained violating material or ended early")]
    InvalidHeader,
    #[error("failed while trying to parse a handshake message")]
    InvalidHandshake,
    #[error("received either a REALLY unfortunate random, or a replayed handshake message")]
    ReplayedHandshake,
    #[error("an unknown packet type \"0x{0:02x}\" was received in a non-handshake packet frame")]
    UnknownMessageType(u8),
    #[error("an advertised message was larger then expected")]
    HandshakePayloadTooLarge,
    #[error("message was zero-length when its record kind forbids it")]
    InvalidEmptyPayload,
    #[error("message was not acceptable in the present context")]
    InvalidContext,
}

impl From<InvalidMessage> for Error {
    #[inline]
    fn from(e: InvalidMessage) -> Self {
        Self::InvalidMessage(e)
    }
}

impl From<InvalidMessage> for std::io::Error {
    #[inline]
    fn from(e: InvalidMessage) -> Self {
        Self::other(e)
    }
}
