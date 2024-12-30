//! Collection of Traits used by the O5 transport implementation

pub trait Digest:
    digest::Digest + digest::core_api::BlockSizeUser + digest::FixedOutputReset + Named + Clone
{
}

impl<
        D: digest::Digest + digest::core_api::BlockSizeUser + digest::FixedOutputReset + Named + Clone,
    > Digest for D
{
}

pub(crate) trait Named {
    const NAME: &str;
}

impl Named for kemeleon::MlKem768 {
    const NAME: &str = "ml-kem768";
}

impl Named for sha3::Sha3_256 {
    const NAME: &str = "sha3-256";
}
