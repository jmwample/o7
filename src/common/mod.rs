use crate::Result;

use colored::Colorize;
use hmac::{digest::Reset, Hmac, Mac};
use sha2::{Sha256, Sha256VarCore};

mod skip;
pub use skip::AsyncDiscard;
// pub use skip::{AsyncDiscard, AsyncSkipReader, Discard, SkipReader};

pub mod elligator2;

pub mod drbg;
pub mod ntor;
pub mod probdist;
pub mod replay_filter;

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
    let r = 0xff & id[0];
    let g = 0xff & id[1];
    let b = 0xff & id[2];
    hex::encode(id).truecolor(r, g, b).to_string()
}
