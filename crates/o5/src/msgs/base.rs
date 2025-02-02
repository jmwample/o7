// TODO: drbg for size sampling
// use crate::common::drbg,
use crate::{constants::*, framing::FrameError, msgs::InvalidMessage, Error};

use bytes::Bytes;
use ptrs::trace;
use tokio_util::bytes::{Buf, BufMut};

use core::fmt;

pub type MessageType = u8;
pub trait Message {
    type Output;
    fn as_pt(&self) -> MessageType;

    fn marshall<T: BufMut>(&self, dst: &mut T) -> Result<(), Error>;

    fn try_parse<T: BufMut + Buf>(buf: &mut T) -> Result<Self::Output, Error>;
}

/// Frames are:
/// ```txt
///    +-----
///    | type      u8;               // Message Type
/// M1 | length    u16               // Message Length (Big Endian).
///    | payload   [u8; length];     // Message Data
///    +-----
///    ...      //  (optional) more messages M2, M3 ...
///    +-----
///    | type      \x00   // minimum padding is 3 bytes (type=\x00  + u16 pad_len=\x00\x00)
/// PAD| pad_len    u16
///    | padding   [0u8; pad_len];
///    +-----
/// ```
///
/// Frames must always be composed of COMPLETE mesages, i.e. a message should
/// never be split across multiple frames.
pub fn build_and_marshall<T: BufMut>(
    dst: &mut T,
    pt: MessageType,
    data: impl AsRef<[u8]>,
    pad_len: usize,
) -> Result<(), Error> {
    // is the provided pad_len too long?
    if pad_len > u16::MAX as usize {
        Err(FrameError::InvalidPayloadLength(pad_len))?
    }

    // is the provided data a reasonable size?
    let buf = data.as_ref();
    let total_size = buf.len() + pad_len;
    trace!(
        "building: total size = {}+{}={} / {MAX_MESSAGE_PAYLOAD_LENGTH}",
        buf.len(),
        pad_len,
        total_size,
    );
    if total_size >= MAX_MESSAGE_PAYLOAD_LENGTH {
        Err(FrameError::InvalidPayloadLength(total_size))?
    }

    dst.put_u8(pt);
    dst.put_u16(buf.len() as u16);
    dst.put(buf);
    if pad_len != 0 {
        dst.put_bytes(0_u8, pad_len);
    }
    Ok(())
}

/// An arbitrary, unknown-content, u16-length-prefixed payload
#[derive(Clone, Eq, PartialEq)]
pub struct PayloadU16(pub Vec<u8>);

impl PayloadU16 {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    pub fn encode_slice<B: BufMut>(slice: &[u8], buf: &mut B) {
        (slice.len() as u16).encode(buf);
        buf.put_slice(slice);
    }
}

impl Codec<'_> for PayloadU16 {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        Self::encode_slice(&self.0, buf);
    }

    fn read<B: Buf>(r: &mut B) -> Result<Self, InvalidMessage> {
        let len = u16::read(r)? as usize;
        if !r.has_remaining() || r.remaining() < len {
            return Err(InvalidMessage::MessageTooShort);
        }
        let mut body = vec![];
        body.put(r.take(len));

        Ok(Self(body))
    }
}

impl fmt::Debug for PayloadU16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, &self.0)
    }
}

// Format an iterator of u8 into a hex string
pub(super) fn hex<'a>(
    f: &mut fmt::Formatter<'_>,
    payload: impl IntoIterator<Item = &'a u8>,
) -> fmt::Result {
    for b in payload {
        write!(f, "{:02x}", b)?;
    }
    Ok(())
}

/// Trait for implementing encoding and decoding functionality
/// on something.
pub trait Codec<'a>: fmt::Debug + Sized {
    /// Function for encoding itself by appending itself to
    /// the provided writable Buffer object.
    fn encode<B: BufMut>(&self, buf: &mut B);

    /// Function for decoding itself from the provided reader
    /// will return Some if the decoding was successful or
    /// None if it was not.
    fn read<B: Buf>(_: &mut B) -> Result<Self, InvalidMessage>;

    /// Convenience function for encoding the implementation
    /// into a vec and returning it
    fn get_encoding(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.encode(&mut bytes);
        bytes
    }

    /// Function for wrapping a call to the read function in
    /// a Reader for the slice of bytes provided
    ///
    /// Returns `Err(InvalidMessage::ExcessData(_))` if
    /// `Self::read` does not read the entirety of `bytes`.
    fn read_bytes(mut buf: &'a [u8]) -> Result<Self, InvalidMessage> {
        // let mut reader = Bytes::from(buf);
        Self::read(&mut buf).and_then(|r| {
            if buf.has_remaining() {
                Err(InvalidMessage::ExcessData("read_bytes"))
            } else {
                Ok(r)
            }
        })
    }
}

impl Codec<'_> for u8 {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(*self);
    }

    fn read<B: Buf>(r: &mut B) -> Result<Self, InvalidMessage> {
        if r.has_remaining() {
            Ok(r.get_u8())
        } else {
            Err(InvalidMessage::MissingData("u8"))
        }
    }
}

pub(crate) fn put_u16(v: u16, out: &mut [u8]) {
    let out: &mut [u8; 2] = (&mut out[..2]).try_into().unwrap();
    *out = u16::to_be_bytes(v);
}

impl Codec<'_> for u16 {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        let mut b16 = [0u8; 2];
        put_u16(*self, &mut b16);
        buf.put_slice(&b16);
    }

    fn read<B: Buf>(r: &mut B) -> Result<Self, InvalidMessage> {
        if r.has_remaining() && r.remaining() >= 2 {
            Ok(r.get_u16())
        } else {
            Err(InvalidMessage::MissingData("u16"))
        }
    }
}
