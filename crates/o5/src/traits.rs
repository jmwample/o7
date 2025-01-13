//! Collection of Traits used by the O5 transport implementation

use typenum::Unsigned;

pub trait Named {
    const NAME: &str;
}

impl Named for kemeleon::MlKem768 {
    const NAME: &str = "ml-kem768";
}

impl Named for sha3::Sha3_256 {
    const NAME: &str = "sha3-256";
}

pub trait Digest:
    digest::Digest + digest::core_api::BlockSizeUser + digest::FixedOutputReset + Named + Clone
{
}

impl<
        D: digest::Digest + digest::core_api::BlockSizeUser + digest::FixedOutputReset + Named + Clone,
    > Digest for D
{
}

pub trait OKemCore: kemeleon::OKemCore + Named {}
impl<O: kemeleon::OKemCore + Named> OKemCore for O {}

pub trait DigestSizes: Digest {
    /// Size of an authentication value in bytes
    const AUTH_SIZE: usize;
    /// Size of the digest used for the mark in the o5 handshake
    const MARK_SIZE: usize;
    /// Size of the digest used for the MAC in the o5 handshake
    const MAC_SIZE: usize;
}

impl<D: Digest> DigestSizes for D {
    const AUTH_SIZE: usize = <D as digest::OutputSizeUser>::OutputSize::USIZE;
    const MARK_SIZE: usize = <D as digest::OutputSizeUser>::OutputSize::USIZE;
    const MAC_SIZE: usize = <D as digest::OutputSizeUser>::OutputSize::USIZE;
}

pub trait FramingSizes: OKemCore {
    const CT_SIZE: usize;
    const EK_SIZE: usize;
}

impl<K: OKemCore> FramingSizes for K {
    const CT_SIZE: usize =
        <<K as kemeleon::OKemCore>::Ciphertext as kemeleon::Encode>::EncodedSize::USIZE;
    const EK_SIZE: usize =
        <<K as kemeleon::OKemCore>::EncapsulationKey as kemeleon::Encode>::EncodedSize::USIZE;
}
