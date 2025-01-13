/// Package framing implements the obfs4 link framing and cryptography.
///
/// The Encoder/Decoder shared secret format is:
///
/// ```txt
///     NaCl_secretbox_key  [u8; 32];
///     NaCl_Nonce_prefix   [u8; 16];
///     SipHash_24_key      [u8; 16]; // (used to obfsucate length)
///     SipHash_24_IV       [u8; 8];
/// ```
///
/// The frame format is:
///
/// ```txt
///     length      u16; // (obfsucated, big endian)
///     // NaCl secretbox (Poly1305/XChaCha20) containing:
///         tag     [u8; 16]; // (Part of the secretbox construct)
///         payload [u8];
/// ```
///
/// The length field is length of the NaCl secretbox XORed with the truncated
/// SipHash-2-4 digest ran in OFB mode.
///
/// ```txt
///     // Initialize K, IV[0] with values from the shared secret.
///     // On each packet, IV[n] = H(K, IV[n - 1])
///     // mask_n = IV[n][0:2]
///     // obfs_len = length ^ mask[n]
/// ```
///
/// The NaCl secretbox (Poly1305/XChaCha20) nonce format is:
///
/// ```txt
///     prefix  [u8; 24]; //(Fixed)
///     counter u64; // (Big endian)
/// ```
///
/// The counter is initialized to 1, and is incremented on each frame.  Since
/// the protocol is designed to be used over a reliable medium, the nonce is not
/// transmitted over the wire as both sides of the conversation know the prefix
/// and the initial counter value.  It is imperative that the counter does not
/// wrap, and sessions MUST terminate before 2^64 frames are sent.
use crate::common::drbg;
use bytes::{Buf, BufMut};

mod messages_base;
pub use messages_base::*;

mod messages_v1;
pub use messages_v1::{MessageTypes, Messages};

mod codecs;
pub use codecs::EncryptingCodec as O5Codec;

pub(crate) mod handshake;
pub use handshake::*;

/// MaximumSegmentLength is the length of the largest possible segment
/// including overhead.
pub(crate) const MAX_SEGMENT_LENGTH: usize = 1500 - (40 + 12);

/// secret box overhead is fixed length prefix and counter
const SECRET_BOX_OVERHEAD: usize = TAG_SIZE;

/// FrameOverhead is the length of the framing overhead.
pub(crate) const FRAME_OVERHEAD: usize = LENGTH_LENGTH + SECRET_BOX_OVERHEAD;

/// MaximumFramePayloadLength is the length of the maximum allowed payload
/// per frame.
pub(crate) const MAX_FRAME_PAYLOAD_LENGTH: usize = MAX_SEGMENT_LENGTH - FRAME_OVERHEAD;

// pub(crate) const MAX_FRAME_LENGTH: usize = MAX_SEGMENT_LENGTH - LENGTH_LENGTH;
// pub(crate) const MIN_FRAME_LENGTH: usize = FRAME_OVERHEAD - LENGTH_LENGTH;

pub(crate) const NONCE_PREFIX_LENGTH: usize = 16;
// pub(crate) const NONCE_COUNTER_LENGTH: usize = 8;
// pub(crate) const NONCE_LENGTH: usize = NONCE_PREFIX_LENGTH + NONCE_COUNTER_LENGTH;

/// length in bytes of the `Length` field at the front of a Frame. Converted to
/// big-endian u16 when decoding.
pub(crate) const LENGTH_LENGTH: usize = 2;

/// KEY_LENGTH is the length of the Encoder/Decoder secret key.
pub(crate) const KEY_LENGTH: usize = 32;

/// Size of the HMAC tag used for the frame security.
pub(crate) const TAG_SIZE: usize = 16;

/// This is the expected length of the Key material that is used to seed the
/// encrypting / decryptong codec, i.e. in framing/codec and handshake/
pub(crate) const KEY_MATERIAL_LENGTH: usize = KEY_LENGTH + NONCE_PREFIX_LENGTH + drbg::SEED_LENGTH;

pub trait Marshall {
    fn marshall(&mut self, buf: &mut impl BufMut) -> Result<(), FrameError>;
}

pub trait TryParse {
    type Output;
    fn try_parse(&mut self, buf: &mut impl Buf) -> Result<Self::Output, FrameError>
    where
        Self: Sized;
}

impl std::error::Error for FrameError {}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// is the error returned when [`encode`] rejects the payload length.
    InvalidPayloadLength(usize),

    /// A cryptographic error occurred.
    Crypto(crypto_secretbox::Error),

    /// Failed to marshall a frame or packet,
    FailedToMarshall(String),

    /// An error occurred with the I/O processing
    IO(String),

    /// Returned when [`decode`] requires more data to continue.
    EAgain,

    /// Returned when [`decode`] failed to authenticate a frame.
    TagMismatch,

    /// Returned when the NaCl secretbox nonce's counter wraps (FATAL).
    NonceCounterWrapped,

    /// Returned when the buffer provided for writing a frame is too small.
    ShortBuffer,

    /// Error indicating that a message decoded, or a message provided for
    /// encoding is of an inappropriate type for the context.
    InvalidMessage,

    /// Failed while trying to parse a handshake message
    InvalidHandshake,

    /// Received either a REALLY unfortunate random, or a replayed handshake message
    ReplayedHandshake,

    /// An unknown packet type was received in a non-handshake packet frame.
    UnknownMessageType(u8),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FrameError::InvalidPayloadLength(s) => {
                write!(f, "framing: Invalid payload length: {s}")
            }
            FrameError::Crypto(e) => write!(f, "framing: Secretbox encrypt/decrypt error: {e}"),
            FrameError::FailedToMarshall(s) => write!(f, "Frame or Packet failed to marshall: {s}"),
            FrameError::IO(e) => {
                write!(f, "framing: i/o error occured while processing frame: {e}")
            }
            FrameError::EAgain => write!(f, "framing: more data needed to decode"),
            FrameError::TagMismatch => write!(f, "framing: Poly1305 tag mismatch"),
            FrameError::NonceCounterWrapped => write!(f, "framing: Nonce counter wrapped"),
            FrameError::ShortBuffer => write!(
                f,
                "framing: provided bytes buffer was too short for payload"
            ),
            FrameError::InvalidMessage => write!(f, "framing: incorrect message for context"),
            FrameError::InvalidHandshake => write!(f, "framing: failed to parse handshake message"),
            FrameError::ReplayedHandshake => write!(f, "framing: handshake replayed within TTL"),
            FrameError::UnknownMessageType(pt) => write!(f, "framing: unknown packet type ({pt})"),
        }
    }
}

impl From<crypto_secretbox::Error> for FrameError {
    fn from(value: crypto_secretbox::Error) -> Self {
        FrameError::Crypto(value)
    }
}

impl From<std::io::Error> for FrameError {
    fn from(value: std::io::Error) -> Self {
        FrameError::IO(value.to_string())
    }
}

impl From<FrameError> for std::io::Error {
    fn from(value: FrameError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, format!("{}", value))
    }
}

#[cfg(test)]
mod generic_test;
#[cfg(test)]
mod testing;
