use ptrs::trace;
/// The replayfilter module implements a generic replay detection filter with a
/// caller specifiable time-to-live.  It only detects if a given byte sequence
/// has been seen before based on the SipHash-2-4 digest of the sequence.
/// Collisions are treated as positive matches, though the probability of this
/// happening is negligible.
use siphasher::{prelude::*, sip::SipHasher24};

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// maxFilterSize is the maximum capacity of a replay filter.  This value is
// more as a safeguard to prevent runaway filter growth, and is sized to be
// serveral orders of magnitude greater than the number of connections a busy
// bridge sees in one day, so in practice should never be reached.
const MAX_FILTER_SIZE: usize = 100 * 1024;

#[derive(Clone, PartialEq)]
struct Entry {
    digest: u64,
    first_seen: Instant,
}

// ReplayFilter is a simple filter designed only to detect if a given byte
// sequence has been seen in the recent history.
pub struct ReplayFilter(Arc<Mutex<InnerReplayFilter>>);

impl ReplayFilter {
    pub fn new(ttl: Duration) -> Self {
        Self(Arc::new(Mutex::new(InnerReplayFilter::new(
            ttl,
            MAX_FILTER_SIZE,
        ))))
    }

    // Queries the filter for a given byte sequence, inserts the
    // sequence, and returns if it was present before the insertion operation.
    pub fn test_and_set(&self, now: Instant, buf: impl AsRef<[u8]>) -> bool {
        let mut inner = self.0.lock().unwrap();
        inner.test_and_set(now, buf)
    }
}

struct InnerReplayFilter {
    filter: HashMap<u64, Entry>,
    fifo: VecDeque<Entry>,

    key: [u8; 16],
    ttl_limit: Duration,
    max_cap: usize,
}

impl InnerReplayFilter {
    fn new(ttl_limit: Duration, max_cap: usize) -> Self {
        let mut key = [0_u8; 16];
        getrandom::getrandom(&mut key).unwrap();

        Self {
            filter: HashMap::new(),
            fifo: VecDeque::new(),
            key,
            ttl_limit,
            max_cap,
        }
    }

    fn test_and_set(&mut self, now: Instant, buf: impl AsRef<[u8]>) -> bool {
        self.garbage_collect(now);

        let mut hash = SipHasher24::new_with_key(&self.key);
        let digest: u64 = {
            hash.write(buf.as_ref());
            hash.finish().to_be()
        };

        trace!("checking inner");
        if self.filter.contains_key(&digest) {
            return true;
        }

        trace!("not found: {digest}... inserting");
        let e = Entry {
            digest,
            first_seen: now,
        };

        self.fifo.push_front(e.clone());
        self.filter.insert(digest, e);

        trace!("inserted: {}", self.filter.len());
        false
    }

    fn garbage_collect(&mut self, now: Instant) {
        if self.fifo.is_empty() {
            return;
        }

        while !self.fifo.is_empty() {
            let e = match self.fifo.back() {
                Some(e) => e,
                None => return,
            };

            trace!(
                "{}/{}[/{}] - {:?}",
                self.fifo.len(),
                self.filter.len(),
                self.max_cap,
                self.ttl_limit
            );
            // If the filter is not full, only purge entries that have exceedded
            // the TTL, otherwise purge one entry and test to see if we are
            // still over max length. This should not (typically) be possible as
            // we garbage collect on insert.
            if self.fifo.len() < self.max_cap && self.ttl_limit > Duration::from_millis(0) {
                let delta_t = now - e.first_seen;
                trace!("{:?} > {:?}", now, e.first_seen);
                if now < e.first_seen {
                    trace!("Invalid time");
                    // Aeeeeeee, the system time jumped backwards, potentially by
                    // a lot.  This will eventually self-correct, but "eventually"
                    // could be a long time.  As much as this sucks, jettison the
                    // entire filter.
                    self.reset();
                    return;
                } else if delta_t < self.ttl_limit {
                    return;
                }
            }

            trace!("removing entry");
            // remove the entry
            _ = self.filter.remove(&e.digest);
            _ = self.fifo.pop_back();
        }
    }

    fn reset(&mut self) {
        trace!("RESETING");
        self.filter = HashMap::new();
        self.fifo = VecDeque::new();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::init_subscriber;
    use crate::Result;

    #[test]
    fn replay_filter_ops() -> Result<()> {
        init_subscriber();
        let ttl = Duration::from_secs(10);

        let f = &mut ReplayFilter::new(ttl);

        let buf = b"For a moment, nothing happened. Then, after a second or so, nothing continued to happen.";
        let mut now = Instant::now();

        // test_and_set into empty filter, returns false (not present).
        assert!(
            !f.test_and_set(now, buf),
            "test_and_set (mutex) empty filter returned true"
        );

        // test_and_set into filter containing entry, should return true(present).
        assert!(
            f.test_and_set(now, buf),
            "test_and_set (mutex) populated filter (replayed) returned false"
        );

        let f = &mut InnerReplayFilter::new(ttl, 2);

        // test_and_set into empty filter, returns false (not present).
        assert!(
            !f.test_and_set(now, buf),
            "test_and_set empty filter returned true"
        );

        // test_and_set into filter containing entry, should return true(present).
        assert!(
            f.test_and_set(now, buf),
            "test_and_set populated filter (replayed) returned false"
        );

        // test_and_set with time advanced.
        let buf2 = b"We demand rigidly defined areas of doubt and uncertainty!";
        now += ttl;
        assert!(
            !f.test_and_set(now, buf2),
            "test_and_set populated filter, 2nd entry returned true"
        );
        assert!(
            f.test_and_set(now, buf2),
            "test_and_set populated filter, 2nd entry (replayed) returned false"
        );

        // Ensure that the first entry has been removed by compact.
        assert!(
            !f.test_and_set(now, buf),
            "test_and_set populated filter, compact check returned true"
        );

        // Ensure that the filter gets reaped if the clock jumps backwards.
        now = Instant::now();
        assert!(
            !f.test_and_set(now, buf),
            "test_and_set populated filter, backward time jump returned true"
        );
        assert_eq!(
            f.fifo.len(),
            1,
            "filter fifo has a unexpected number of entries: {}",
            f.fifo.len()
        );
        assert_eq!(
            f.filter.len(),
            1,
            "filter map has a unexpected number of entries: {}",
            f.filter.len()
        );

        // Ensure that the entry is properly added after reaping.
        assert!(
            f.test_and_set(now, buf),
            "test_and_set populated filter, post-backward clock jump (replayed) returned false"
        );

        // Ensure that when the capacity limit is hit entries are evicted
        f.test_and_set(now, "message2");
        for i in 0..10 {
            assert_eq!(
                f.fifo.len(),
                2,
                "filter fifo has a unexpected number of entries: {}",
                f.fifo.len()
            );
            assert_eq!(
                f.filter.len(),
                2,
                "filter map has a unexpected number of entries: {}",
                f.filter.len()
            );
            assert!(
                !f.test_and_set(now, format!("message-1{i}")),
                "unique message failed insert (returned true)"
            );
        }

        Ok(())
    }
}
