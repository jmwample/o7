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

#[derive(Debug, PartialEq, )]
pub enum Extensions {
        Padding,
        PrngSeed(PrngSeedExt),
        ClientParams(),
        ServerParams(),
        CipherSuiteOffer(),
        CipherSuiteAccept(),
        Other(OtherExt),
}

impl Codec<'_> for Extensions {
    fn encode<B: BufMut>(&self, bytes: &mut B) {
    }

    fn read<B: Buf>(r: &mut B) -> Result<Self, InvalidMessage> {
    }
}

impl Codec<'_> for Vec<Extensions> {
    fn encode<B: BufMut>(&self, bytes: &mut B) {
    }

    fn read<B: Buf>(r: &mut B) -> Result<Self, InvalidMessage> {
        Ok(Vec::new())
    }
}

impl Extensions {
    fn encode_many<B: BufMut>(exts: impl AsRef<[Self]> , r: &mut B) {
        exts.as_ref().into_iter().for_each(|ext| ext.encode(r));
    }
}

/// As part of the obfs5 handshake the server should always include a Prng Seed
/// in their response message indicating a successful handshake.
#[derive(Clone, Debug, PartialEq)]
pub struct PrngSeedExt (pub(crate) Seed);

impl Codec<'_> for PrngSeedExt {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.0.as_bytes().iter().for_each(|b| b.encode(buf));
    }

    fn read<B: Buf>(r: &mut B) -> Result<Self, InvalidMessage> {
        let p = PayloadU16::read(r)?;
        if p.0.len() != Seed::BYTE_LEN {
            return Err(InvalidMessage::InvalidDeviation("incorrect length for prngseed ext"));
        }

        let body = Seed::try_from(p.0)
            .map_err(|_| InvalidMessage::InvalidDeviation("this error should not be possible"))?;
        Ok(Self(body))
    }
}

impl From<[u8; Seed::BYTE_LEN]> for PrngSeedExt {
    fn from(value: [u8; Seed::BYTE_LEN]) -> Self {
        Self( Seed::from(value) )
    }
}

/// Extension other than those predefined in this library.
#[derive(Clone, Debug, PartialEq)]
pub struct OtherExt {
    pub(crate) typ: ExtensionType,
    pub(crate) payload: PayloadU16,
}

impl OtherExt {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload.encode(bytes);
    }

    fn read<B: Buf>(typ: ExtensionType, r: &mut B) -> Result<Self, InvalidMessage> {
        let payload = PayloadU16::read(r)?;
        Ok(Self { typ, payload })
    }
}

enum_builder! {
    /// The `ExtensionType` protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    #[repr(u16)]
    pub enum ExtensionType {
        // We definitely want these
        Padding => 0x0000,
        ClientParams => 0x0001,
        ServerParams => 0x0002,
        PrngSeed => 0x0003,

        CipherSuiteOffer => 0x0010,
        CipherSuiteAccept => 0x0011,



        // // We maybe want these
        // ClientAuthz => 0x0011,
        // ServerAuthz => 0x0012,
        // SessionTicket => 0x0023,
        // EarlyData => 0x002a,
        // TransportParameters => 0x0039,

        // // We probably don't need these
        // ServerName => 0x0000,
        // MaxFragmentLength => 0x0001,
        // ClientCertificateUrl => 0x0002,
        // TrustedCAKeys => 0x0003,
        // TruncatedHMAC => 0x0004,
        // StatusRequest => 0x0005,
        // UserMapping => 0x0006,
        // CertificateType => 0x0009,
        // EllipticCurves => 0x000a,
        // ECPointFormats => 0x000b,
        // SRP => 0x000c,
        // SignatureAlgorithms => 0x000d,
        // UseSRTP => 0x000e,
        // ALProtocolNegotiation => 0x0010,
        // SCT => 0x0012,
        // ClientCertificateType => 0x0013,
        // ServerCertificateType => 0x0014,
        // ExtendedMasterSecret => 0x0017,
        // CompressCertificate => 0x001b,
        // PreSharedKey => 0x0029,
        // SupportedVersions => 0x002b,
        // Cookie => 0x002c,
        // PSKKeyExchangeModes => 0x002d,
        // TicketEarlyDataInfo => 0x002e,
        // CertificateAuthorities => 0x002f,
        // OIDFilters => 0x0030,
        // PostHandshakeAuth => 0x0031,
        // SignatureAlgorithmsCert => 0x0032,
        // KeyShare => 0x0033,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{Rng, RngCore};
    use crate::test_utils::init_subscriber;

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
