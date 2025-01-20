///
/// # DRBG
///
/// Implements a simple Hash based Deterministic Random Bit Generator (DRBG)
/// algorithm in order to match the golang implementation of obfs4.
use crate::{Error, Result};

use std::fmt;
use std::str::FromStr;

use getrandom::getrandom;
use hex::FromHex;
use rand_core::{impls, Error as RandError, RngCore};
use siphasher::{prelude::*, sip::SipHasher24};

pub(crate) const SIZE: usize = 8;
pub(crate) const SEED_LENGTH: usize = 16 + SIZE;

/// Hash-DRBG seed
#[derive(Debug, PartialEq, Clone)]
pub struct Seed([u8; SEED_LENGTH]);

impl Seed {

    pub const BYTE_LEN: usize = SEED_LENGTH;

    pub fn new() -> Result<Self> {
        let mut seed = Self([0_u8; SEED_LENGTH]);
        getrandom(&mut seed.0)?;
        Ok(seed)
    }

    // Calling unwraps here is safe because the size of the key is fixed
    fn to_pieces(&self) -> ([u8; 16], [u8; SIZE]) {
        let key: [u8; 16] = self.0[..16].try_into().unwrap();

        let ofb: [u8; SIZE] = self.0[16..].try_into().unwrap();
        (key, ofb)
    }

    fn to_new_drbg(&self) -> Drbg {
        let (key, ofb) = self.to_pieces();
        Drbg {
            hash: SipHasher24::new_with_key(&key),
            ofb,
        }
    }

    pub fn to_bytes(&self) -> [u8; SEED_LENGTH] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl FromHex for Seed {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(msg: T) -> Result<Self> {
        let buffer = <[u8; SEED_LENGTH]>::from_hex(msg)?;
        Ok(Seed(buffer))
    }
}

impl TryFrom<String> for Seed {
    type Error = Error;

    fn try_from(msg: String) -> Result<Self> {
        let buffer = <[u8; SEED_LENGTH]>::from_hex(msg)?;
        Ok(Seed(buffer))
    }
}

impl TryFrom<&String> for Seed {
    type Error = Error;

    fn try_from(msg: &String) -> Result<Self> {
        let buffer = <[u8; SEED_LENGTH]>::from_hex(msg)?;
        Ok(Seed(buffer))
    }
}

impl TryFrom<&str> for Seed {
    type Error = Error;

    fn try_from(msg: &str) -> Result<Self> {
        let buffer = <[u8; SEED_LENGTH]>::from_hex(msg)?;
        Ok(Seed(buffer))
    }
}

impl FromStr for Seed {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Seed::from_hex(s)
    }
}

impl TryFrom<&[u8]> for Seed {
    type Error = Error;
    fn try_from(arr: &[u8]) -> Result<Self> {
        let mut seed = Seed::new()?;
        if arr.len() != SEED_LENGTH {
            let e = format!("incorrect drbg seed length {}!={SEED_LENGTH}", arr.len());
            return Err(Error::Other(e.into()));
        }

        seed.0 = arr
            .try_into()
            .map_err(|e| Error::Other(format!("{e}").into()))?;

        Ok(seed)
    }
}

impl From<[u8; SEED_LENGTH]> for Seed {
    fn from(arr: [u8; SEED_LENGTH]) -> Self {
        Seed(arr)
    }
}

impl TryFrom<Vec<u8>> for Seed {
    type Error = Error;
    fn try_from(arr: Vec<u8>) -> Result<Self> {
        Seed::try_from(arr.as_slice())
    }
}

impl fmt::Display for Seed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..]))
    }
}

pub struct Drbg {
    #[allow(deprecated)]
    hash: SipHasher24,
    ofb: [u8; SIZE],
}

impl Drbg {
    /// Makes a 'Drbg' instance based off an optional seed.  The seed
    /// is truncated to SeedLength.
    pub fn new(seed_in: Option<Seed>) -> Result<Self> {
        let seed = match seed_in {
            Some(s) => s,
            None => Seed::new()?,
        };
        Ok(seed.to_new_drbg())
    }

    /// Returns a uniformly distributed random uint [0, 1 << 64).
    pub fn uint64(&mut self) -> u64 {
        let ret: u64 = {
            self.hash.write(&self.ofb[..]);
            self.hash.finish().to_be()
        };
        self.ofb = ret.to_be_bytes();

        ret
    }

    /// returns a random u16 selected in the same way as the golang implementation
    /// of obfs4 which takes the high bits when casting to u16.
    pub(crate) fn length_mask(&mut self) -> u16 {
        let ret: u64 = {
            self.hash.write(&self.ofb[..]);
            self.hash.finish().to_be()
        };
        self.ofb = ret.to_be_bytes();

        (ret >> 48) as u16
    }

    /// Returns a uniformly distributed random integer [0, 1 << 63).
    pub fn int63(&mut self) -> i64 {
        let mut ret = self.uint64();

        // This is a safe unwrap as we bit-mask to below overflow
        // ret &= (1<<63) -1;
        ret &= <i64 as TryInto<u64>>::try_into(i64::MAX).unwrap();
        i64::try_from(ret).unwrap()
    }

    /// NextBlock returns the next 8 byte DRBG block.
    pub fn next_block(&mut self) -> [u8; SIZE] {
        let h = self.uint64();
        h.to_be_bytes()
    }
}

impl RngCore for Drbg {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.uint64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn rand() -> Result<()> {
        let seed = Seed::new()?;

        let mut drbg = Drbg::new(Some(seed))?;

        let mut u: u64;
        let mut i: i64;
        for n in 0..100_000 {
            i = drbg.int63();
            assert!(i > 0, "i63 error - {i} < 0  iter:{n}");

            u = drbg.uint64();
            assert_ne!(u, 0);
        }

        Ok(())
    }

    #[test]
    fn from_() -> Result<()> {
        let expected = Seed([0_u8; SEED_LENGTH]);

        let input = "000000000000000000000000000000000000000000000000";
        assert_eq!(Seed::try_from(input).unwrap(), expected);
        assert_eq!(Seed::from_hex(input).unwrap(), expected);
        assert_eq!(Seed::from_str(input).unwrap(), expected);

        let input: String = input.into();
        assert_eq!(Seed::try_from(input.clone()).unwrap(), expected);
        assert_eq!(Seed::from_hex(input.clone()).unwrap(), expected);
        assert_eq!(Seed::try_from(&input.clone()).unwrap(), expected);
        assert_eq!(Seed::from_hex(input.clone()).unwrap(), expected);
        assert_eq!(Seed::from_str(&input.clone()).unwrap(), expected);

        let input = [0_u8; SEED_LENGTH];
        assert_eq!(Seed::from(input), expected);
        assert_eq!(Seed::try_from(&input[..]).unwrap(), expected);

        let input = vec![0_u8; SEED_LENGTH];
        assert_eq!(Seed::try_from(input.clone()).unwrap(), expected);
        assert_eq!(Seed::try_from(&input.clone()[..]).unwrap(), expected);

        Ok(())
    }

    /// Make sure bitmasks, overflows, and type assertions work the way I think they do.
    #[test]
    fn conversions() {
        let mut u64_max = u64::MAX;
        <u64 as TryInto<i64>>::try_into(u64_max).unwrap_err();

        u64_max &= <i64 as TryInto<u64>>::try_into(i64::MAX).unwrap();
        let i: i64 = u64_max.try_into().unwrap();
        // println!("{i:x}, {:x}", i64::MAX);
        assert_eq!(i, i64::MAX);

        let mut u64_max = u64::MAX;
        u64_max &= (1 << 63) - 1;
        let i: i64 = u64_max.try_into().unwrap();
        assert_eq!(i, i64::MAX);
        assert_eq!(i, i64::MAX);

        let u64_max: u64 = (1 << 63) - 1;
        let i: i64 = u64_max.try_into().unwrap();
        assert_eq!(i, i64::MAX);
        assert_eq!(i, i64::MAX);
    }

    /// Ensure that we are compatible with the golang hash-drbg so that the
    /// libraries are interchangeable.
    #[test]
    fn sample_compat_compare() -> Result<()> {
        struct Case {
            seed: &'static str,
            out: Vec<i64>,
        }

        // if we can generate multiple correct rounds for multiple seeds we should be just fine.
        let cases = vec![
            Case {
                seed: "000000000000000000000000000000000000000000000000",
                out: vec![
                    7432626515892259304,
                    5773523046280711756,
                    4537542203639783680,
                ],
            },
            // (0, 0) "00000000000000000000000000000000"
            // &{v0:8317987319222330741 v1:7237128888997146477 v2:7816392313619706465 v3:8387220255154660723 } k0:0 k1:0 x:[0 0 0 0 0 0 0 0] nx:0 size:8 t:0}
            // { v0:8317987319222330741 v1:7237128888997146477 v2:7816392313619706465 v3:8387220255154660723 }
            Case {
                seed: "0c10867722204c856e78315d669449dcb6e66f2fe5247a80",
                out: vec![
                    9059004827137905928,
                    6853924365612632173,
                    1485252377529977150,
                ],
            },
            // 854c20227786100c  dc4994665d31786e k0:9605087437680676876 k1:15873381529015122030
            //                                      (9605087437680676876,   15873381529015122030) "0c10867722204c856e78315d669449dc"
            Case {
                seed: "ddbb886aefbe2a65c2509dfc3bb0932c5e881965afca80a0",
                out: vec![
                    3952461850862704951,
                    6715353867928838006,
                    5560038622741453571,
                ],
            },
            Case {
                seed: "e691b1eaa81018e8b16bbf84d71f3ba0c5f965bace2da7cc",
                out: vec![
                    8251725530906761037,
                    5718043109939568014,
                    7585544303175018394,
                ],
            },
        ];

        for (j, c) in cases.into_iter().enumerate() {
            let seed = Seed::try_from(c.seed)?;
            let drbg = &mut Drbg::new(Some(seed))?;
            // println!();
            // println!("{:?}", drbg.hash);

            for (k, expected) in c.out.into_iter().enumerate() {
                let i = drbg.int63();
                // println!("{:?}", drbg.hash);
                assert_eq!(i, expected, "[{},{}]\n0x{i:x}\n0x{expected:x}", j, k);
            }
        }

        Ok(())
    }
}
