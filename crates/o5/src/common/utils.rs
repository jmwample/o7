use crate::{constants::*, traits::DigestSizes, Digest, Result};

use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{CryptoRngCore, RngCore};
use subtle::ConstantTimeEq;

use ptrs::trace;

pub fn get_epoch_hour() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 3600
}

pub fn make_pad(rng: &mut impl CryptoRngCore, pad_len: usize) -> Vec<u8> {
    trace!("[make_hs_pad] generating {pad_len}B");
    let mut pad = vec![u8::default(); pad_len];
    rng.fill_bytes(&mut pad);
    pad
}

pub fn make_hs_pad(pad_len: usize) -> Vec<u8> {
    make_pad(&mut rand::thread_rng(), pad_len)
}

pub fn find_mac_mark<D: Digest>(
    m: impl AsRef<[u8]>,
    buf: impl AsRef<[u8]>,
    start_pos: usize,
    max_pos: usize,
    from_tail: bool,
) -> Option<usize> {
    let mark = m.as_ref();
    if mark.len() != D::MARK_SIZE {
        // Bad expected mark provided.
        return None;
    }

    let buffer = buf.as_ref();
    if buffer.len() < D::MARK_SIZE {
        return None;
    }
    trace!(
        "finding mac mark: buf: {}B, {}-{}, from_tail: {}",
        buffer.len(),
        start_pos,
        max_pos,
        from_tail
    );

    if start_pos > buffer.len() {
        return None;
    }

    let mut end_pos = buffer.len();
    if end_pos > max_pos {
        end_pos = max_pos;
    }

    if end_pos - start_pos < D::MARK_SIZE + D::MAC_SIZE {
        return None;
    }

    let mut pos: usize;
    if from_tail {
        // The server can optimize the search process by only examining the
        // tail of the buffer.  The client can't send valid data past M_C |
        // MAC_C as it does not have the server's public key yet.
        pos = end_pos - (D::MARK_SIZE + D::MAC_SIZE);
        // trace!("{pos}\n{}\n{}", hex::encode(mark), hex::encode(&buffer[pos..pos + D::MARK_SIZE]));
        if mark[..]
            .ct_eq(buffer[pos..pos + D::MARK_SIZE].as_ref())
            .into()
        {
            return Some(pos);
        }
        return None;
    }

    // The client has to actually do a substring search since the server can
    // and will send payload trailing the response.
    //
    // XXX: .windows().position() uses a naive search, which kind of sucks.
    // but better algorithms (like `contains` for String) aren't implemented
    // for byte slices in std.
    pos = buffer[start_pos..end_pos]
        .windows(D::MARK_SIZE)
        .position(|window| window.ct_eq(&mark[..]).into())?;

    // Ensure that there is enough trailing data for the MAC.
    if start_pos + pos + D::MARK_SIZE + D::MAC_SIZE > end_pos {
        return None;
    }

    // Return the index relative to the start of the slice.
    pos += start_pos;
    Some(pos)
}

#[cfg(test)]
mod test {
    use super::*;
    use bytes::Bytes;

    const MARK_LENGTH: usize = <sha3::Sha3_256 as DigestSizes>::MARK_SIZE;
    const MAC_LENGTH: usize = <sha3::Sha3_256 as DigestSizes>::MAC_SIZE;

    struct MacMarkTest {
        mark: [u8; MARK_LENGTH],
        buf: Vec<u8>,
        start_pos: usize,
        max_pos: usize,
        from_tail: bool,
        expected: Option<usize>,
    }

    #[test]
    fn find_mac_mark_thorough() -> Result<()> {
        let cases = vec![
            MacMarkTest {
                mark: [0_u8; MARK_LENGTH],
                buf: vec![0_u8; 100],
                start_pos: 0,
                max_pos: 100,
                from_tail: false,
                expected: Some(0),
            },
            MacMarkTest {
                mark: hex::decode("00112233445566778899aabbccddeeff")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                buf: hex::decode(
                    "00112233445566778899aabbccddeeff00000000000000000000000000000000",
                )
                .unwrap(),
                start_pos: 0,
                max_pos: 100,
                from_tail: false,
                expected: Some(0),
            },
            MacMarkTest {
                // from tail
                mark: hex::decode("00112233445566778899aabbccddeeff")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                buf: hex::decode(
                    "00112233445566778899aabbccddeeff00000000000000000000000000000000",
                )
                .unwrap(),
                start_pos: 0,
                max_pos: 100,
                from_tail: true,
                expected: Some(0),
            },
            MacMarkTest {
                // from tail not align with start
                mark: hex::decode("00112233445566778899aabbccddeeff")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                buf: hex::decode(
                    "000000112233445566778899aabbccddeeff00000000000000000000000000000000",
                )
                .unwrap(),
                start_pos: 0,
                max_pos: 100,
                from_tail: true,
                expected: Some(2),
            },
            MacMarkTest {
                mark: hex::decode("00112233445566778899aabbccddeeff")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                buf: hex::decode(
                    "000000112233445566778899aabbccddeeff00000000000000000000000000000000",
                )
                .unwrap(),
                start_pos: 0,
                max_pos: 100,
                from_tail: false,
                expected: Some(2),
            },
            MacMarkTest {
                mark: hex::decode("00112233445566778899aabbccddeeff")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                buf: hex::decode(
                    "00000000112233445566778899aabbccddeeff00000000000000000000000000000000",
                )
                .unwrap(),
                start_pos: 2,
                max_pos: 100,
                from_tail: false,
                expected: Some(3),
            },
            MacMarkTest {
                // Not long enough to contain MAC
                mark: hex::decode("00112233445566778899aabbccddeeff")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                buf: hex::decode("00112233445566778899aabbccddeeff").unwrap(),
                start_pos: 0,
                max_pos: 100,
                from_tail: false,
                expected: None,
            },
            MacMarkTest {
                // Access from tail success
                mark: [0_u8; MARK_LENGTH],
                buf: vec![0_u8; 100],
                start_pos: 0,
                max_pos: 100,
                from_tail: true,
                expected: Some(100 - MARK_LENGTH - MAC_LENGTH),
            },
            MacMarkTest {
                // from tail fail
                mark: [0_u8; MARK_LENGTH],
                buf: hex::decode(
                    "00112233445566778899aabbccddeeff00000000000000000000000000000000",
                )
                .unwrap(),
                start_pos: 0,
                max_pos: 100,
                from_tail: true,
                expected: None,
            },
            MacMarkTest {
                // provided buf too short
                mark: [0_u8; MARK_LENGTH],
                buf: vec![0_u8; MARK_LENGTH - 1],
                start_pos: 0,
                max_pos: 100,
                from_tail: false,
                expected: None,
            },
            MacMarkTest {
                // provided buf cant contain mark and mac
                mark: [0_u8; MARK_LENGTH],
                buf: vec![0_u8; MARK_LENGTH + MAC_LENGTH - 1],
                start_pos: 0,
                max_pos: 100,
                from_tail: false,
                expected: None,
            },
        ];

        for m in cases {
            let actual = find_mac_mark::<sha3::Sha3_256>(
                m.mark,
                Bytes::from(m.buf),
                m.start_pos,
                m.max_pos,
                m.from_tail,
            );
            assert_eq!(actual, m.expected);
        }

        Ok(())
    }

    #[test]
    fn epoch_format() {
        let _h = format!("{}", get_epoch_hour());
        // println!("{h} {}", hex::encode(h.as_bytes()));
    }
}
