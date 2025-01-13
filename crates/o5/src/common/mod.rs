use crate::Result;

use colored::Colorize;
use hmac::Hmac;
use sha2::Sha256;

pub(crate) mod ct;
pub(crate) mod kdf;
pub(crate) mod utils;

mod skip;
pub use skip::discard;

pub mod drbg;
pub mod ntor_arti;
pub mod probdist;
pub mod replay_filter;
pub mod x25519_elligator2;
// pub mod xwing;

pub trait ArgParse {
    type Output;

    fn parse_args() -> Result<Self::Output>;
}

pub(crate) type HmacSha256 = Hmac<Sha256>;

pub(crate) fn colorize(b: impl AsRef<[u8]>) -> String {
    let id = b.as_ref();
    if id.len() < 3 {
        return hex::encode(id);
    }
    let r = id[0];
    let g = id[1];
    let b = id[2];
    hex::encode(id).truecolor(r, g, b).to_string()
}
