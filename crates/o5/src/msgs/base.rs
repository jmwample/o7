// TODO: drbg for size sampling
// use crate::common::drbg,
use crate::{constants::*, framing::FrameError, msgs::InvalidMessage, Error};

use tokio_util::bytes::{Buf, BufMut};

use ptrs::trace;

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
