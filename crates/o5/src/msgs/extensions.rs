//! O5 Extension usage, construction, and utilities
//!
//! Extensions are formatted in an effectively
//!  +-----
//!  | type      u16;              // Extension Type
//!  | length    u16;              // Extension Payload Length (Big Endian).
//!  | payload   [u8; length];     // Extension Payload Data
//!  +-----

use crate::{
    common::drbg::Seed,
    msgs::{
        base::{Codec, PayloadU16},
        InvalidMessage,
    },
};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use core::fmt::Debug;

#[derive(Debug, PartialEq, Clone)]
pub enum Extensions {
    Padding(usize),
    PrngSeed(PrngSeedExt),
    ClientParams(),
    ServerParams(),
    CipherSuiteOffer(),
    CipherSuiteAccept(),
    RawData(Vec<u8>),

    Ping,
    Pong,

    Other(OtherExt),
}

impl Codec<'_> for Extensions {
    fn encode<B: BufMut>(&self, bytes: &mut B) {}

    fn read<B: Buf>(r: &mut B) -> Result<Self, InvalidMessage> {
        let ext_type = ExtensionType::read(r)?;

        let ext = match ext_type {
            ExtensionType::Padding => {
                let len = u16::read(r)? as usize;
                r.advance(len);
                Extensions::Padding(len)
            }
            ExtensionType::ClientParams => todo!(),
            ExtensionType::ServerParams => todo!(),
            ExtensionType::PrngSeed => Extensions::PrngSeed(PrngSeedExt::read(r)?),
            ExtensionType::RawData => {
                let data = PayloadU16::read(r)?;
                Extensions::RawData(data.0)
            }
            ExtensionType::CipherSuiteOffer => todo!(),
            ExtensionType::CipherSuiteAccept => todo!(),
            ExtensionType::Ping => {
                let len = u16::read(r)? as usize;
                if len != 0 {
                    // Ping should include length of 0x0000_u16
                    r.advance(len);
                }
                Extensions::Ping
            }
            ExtensionType::Pong => {
                let len = u16::read(r)? as usize;
                if len != 0 {
                    // Pong should include length of 0x0000_u16
                    r.advance(len);
                }
                Extensions::Pong
            }
            ExtensionType::Unknown(typ) => Extensions::Other(OtherExt::read(typ, r)?),
        };
        Ok(ext)
    }
}

impl Codec<'_> for Vec<Extensions> {
    fn encode<B: BufMut>(&self, bytes: &mut B) {}

    fn read<B: Buf>(r: &mut B) -> Result<Self, InvalidMessage> {
        Ok(Vec::new())
    }
}

impl Extensions {
    // Encode a set of Extensions into the provided buffer
    pub fn encode_many<B: BufMut>(exts: impl AsRef<[Self]>, r: &mut B) {
        exts.as_ref().into_iter().for_each(|ext| ext.encode(r));
    }

    /// Real all available extensions in the provided buffer
    pub fn read_many<B: Buf>(r: &mut B) -> Result<Vec<Self>, InvalidMessage> {
        Ok(Vec::new()) // TODO
    }
}

/// As part of the obfs5 handshake the server should always include a Prng Seed
/// in their response message indicating a successful handshake.
#[derive(Clone, Debug, PartialEq)]
pub struct PrngSeedExt(pub(crate) Seed);

impl Codec<'_> for PrngSeedExt {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.0.as_bytes().iter().for_each(|b| b.encode(buf));
    }

    fn read<B: Buf>(r: &mut B) -> Result<Self, InvalidMessage> {
        let p = PayloadU16::read(r)?;
        if p.0.len() != Seed::BYTE_LEN {
            return Err(InvalidMessage::InvalidDeviation(
                "incorrect length for prngseed ext",
            ));
        }

        let body = Seed::try_from(p.0)
            .map_err(|_| InvalidMessage::InvalidDeviation("this error should not be possible"))?;
        Ok(Self(body))
    }
}

impl From<[u8; Seed::BYTE_LEN]> for PrngSeedExt {
    fn from(value: [u8; Seed::BYTE_LEN]) -> Self {
        Self(Seed::from(value))
    }
}

/// Extension other than those predefined in this library.
#[derive(Clone, Debug, PartialEq)]
pub struct OtherExt {
    pub(crate) typ: u16,
    pub(crate) payload: PayloadU16,
}

impl OtherExt {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload.encode(bytes);
    }

    fn read<B: Buf>(typ: u16, r: &mut B) -> Result<Self, InvalidMessage> {
        let payload = PayloadU16::read(r)?;
        Ok(Self { typ, payload })
    }
}

enum_builder! {
    /// The `ExtensionType` protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised Type Indicators.
    #[repr(u16)]
    pub enum ExtensionType {
        // We definitely want these
        Padding => 0x0000,
        ClientParams => 0x0001,
        ServerParams => 0x0002,
        PrngSeed => 0x0003,
        RawData => 0x0004,

        CipherSuiteOffer => 0x0010,
        CipherSuiteAccept => 0x0011,

        Ping => 0xff00,
        Pong => 0xff01,

        // // We maybe want these
        // ClientAuthz => 0x0011,
        // ServerAuthz => 0x0012,
        // SessionTicket => 0x0023,
        // EarlyData => 0x002a,
        // TransportParameters => 0x0039,
        // CongestionControl => 0x????,
    }
}

impl Codec<'_> for ExtensionType {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        u16::from(self.clone()).encode(buf);
    }

    fn read<B: Buf>(r: &mut B) -> Result<Self, InvalidMessage> {
        Ok(u16::read(r)?.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::init_subscriber;
    use rand::{Rng, RngCore};

    #[test]
    fn prngseed() -> Result<(), InvalidMessage> {
        init_subscriber();

        let mut buf = BytesMut::new();
        let mut rng = rand::thread_rng();
        let pad_len = rng.gen_range(0..100);
        let mut seed = [0_u8; Seed::BYTE_LEN];
        rng.fill_bytes(&mut seed);

        PrngSeedExt(Seed::from(seed)).encode(&mut buf);
        // build_and_marshall(&mut buf, PrngSeedExt.into(), seed, pad_len)?;

        let pkt = Extensions::read(&mut buf)?;
        assert_eq!(Extensions::PrngSeed(PrngSeedExt::from(seed)), pkt);

        Ok(())
    }
}
