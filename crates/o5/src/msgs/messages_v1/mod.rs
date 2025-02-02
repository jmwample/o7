//! Version 1 of the Protocol Messagess to be included in constructed frames.

use crate::{
    constants::*,
    msgs::{build_and_marshall, InvalidMessage},
    Error,
};

mod prng_seed;

use tokio_util::bytes::{Buf, BufMut};
use tracing::trace;

#[derive(Debug, PartialEq)]
pub enum MessageTypes {
    Padding,
    RawPayload,

    Heartbeat,
}

impl MessageTypes {
    // Steady state message types (and required backwards compatibility messages)
    const PADDING: u8 = 0x00;
    const RAW_PAYLOAD: u8 = 0x01;

    const HEARTBEAT: u8 = 0x10;
}

impl From<MessageTypes> for u8 {
    fn from(value: MessageTypes) -> Self {
        match value {
            MessageTypes::Padding => MessageTypes::PADDING,
            MessageTypes::RawPayload => MessageTypes::RAW_PAYLOAD,

            MessageTypes::Heartbeat => MessageTypes::HEARTBEAT,
        }
    }
}

impl TryFrom<u8> for MessageTypes {
    type Error = InvalidMessage;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            MessageTypes::PADDING => Ok(MessageTypes::Padding),
            MessageTypes::RAW_PAYLOAD => Ok(MessageTypes::RawPayload),
            MessageTypes::HEARTBEAT => Ok(MessageTypes::Heartbeat),
            _ => Err(InvalidMessage::UnknownMessageType(value)),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Messages {
    Padding(u16),
    RawPayload(Vec<u8>),
    Heartbeat,
}

impl Messages {
    pub(crate) fn as_pt(&self) -> MessageTypes {
        match self {
            Messages::Padding(_) => MessageTypes::Padding,
            Messages::RawPayload(_) => MessageTypes::RawPayload,
            Messages::Heartbeat => MessageTypes::Heartbeat,
        }
    }

    pub(crate) fn marshall<T: BufMut>(&self, dst: &mut T) -> Result<(), InvalidMessage> {
        dst.put_u8(self.as_pt().into());
        match self {
            Messages::RawPayload(buf) => {
                dst.put_u16(buf.len() as u16);
                dst.put(&buf[..]);
            }
            Messages::Padding(pad_len) => {
                dst.put_u16(*pad_len);
                if *pad_len > 0 {
                    let buf = vec![0_u8; *pad_len as usize];
                    dst.put(&buf[..]);
                }
            }

            _ => {
                dst.put_u16(0_u16);
            }
        }
        Ok(())
    }

    pub(crate) fn try_parse<T: BufMut + Buf>(buf: &mut T) -> Result<Self, InvalidMessage> {
        if buf.remaining() < MESSAGE_OVERHEAD {
            Err(InvalidMessage::InvalidHeader)?
        }
        let pt: MessageTypes = buf.get_u8().try_into()?;
        let length = buf.get_u16() as usize;

        match pt {
            MessageTypes::Padding => Ok(Messages::Padding(length as u16)),

            MessageTypes::RawPayload => {
                let mut dst = vec![];
                dst.put(buf.take(length));
                trace!("{}B remainng", buf.remaining());
                assert_eq!(buf.remaining(), Self::drain_padding(buf));
                Ok(Messages::RawPayload(dst))
            }

            MessageTypes::Heartbeat => Ok(Messages::Heartbeat),
        }
    }

    fn drain_padding<T: BufMut + Buf>(b: &mut T) -> usize {
        if !b.has_remaining() {
            return 0;
        }

        let length = b.remaining();
        let mut count = length;
        // make a shallow copy that we can work with so that we can continually
        // check first byte without actually removing it (advancing the pointer
        // in the Bytes object).
        let mut buf = b.copy_to_bytes(b.remaining());
        for i in 0..length {
            if buf[0] != 0 {
                count = i;
                break;
            }
            _ = buf.get_u8();
        }

        b.put(buf);
        trace!("drained {count}B, {}B remaining", b.remaining(),);
        count
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::framing::*;
    use crate::test_utils::init_subscriber;

    use rand::prelude::*;
    use tokio_util::bytes::BytesMut;

    #[test]
    fn drain_padding() {
        init_subscriber();
        let test_cases = [
            ("", 0, 0),
            ("00", 1, 0),
            ("0000", 2, 0),
            ("0000000000000000", 8, 0),
            ("000000000000000001", 8, 1),
            ("0000010000000000", 2, 6),
            ("0102030000000000", 0, 8),
        ];

        for case in test_cases {
            let buf = hex::decode(case.0).expect("failed to decode hex");
            let mut b = BytesMut::from(&buf as &[u8]);
            let cnt = Messages::drain_padding(&mut b);
            assert_eq!(cnt, case.1);
            assert_eq!(b.remaining(), case.2);
        }
    }

    #[test]
    fn payload() -> Result<(), Error> {
        init_subscriber();

        let mut buf = BytesMut::new();
        let mut rng = rand::thread_rng();
        let pad_len = rng.gen_range(0..100);
        let mut payload = [0_u8; 1000];
        rng.fill_bytes(&mut payload);

        build_and_marshall(&mut buf, MessageTypes::RawPayload.into(), payload, pad_len)?;

        let pkt = Messages::try_parse(&mut buf)?;
        assert_eq!(Messages::RawPayload(payload.to_vec()), pkt);

        Ok(())
    }
}
