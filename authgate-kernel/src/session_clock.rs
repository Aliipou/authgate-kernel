//! Session-scoped monotonic clock — NOT in the TCB.
//!
//! Callers must not feed externally-controlled wall-clock values into `verify()`
//! without going through this helper. `SessionClock` anchors time to
//! `std::time::Instant` at construction and rejects backward jumps when callers
//! supply their own Unix seconds via [`SessionClock::accept`].
//!
//! See `TCB_DISCIPLINE.md` § Clock integrity (caller obligation).

use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockError {
    /// A caller-supplied `now` moved backward — possible clock tampering.
    BackwardJump { previous: u64, supplied: u64 },
}

/// Monotonic session clock for sequential `verify()` / `CallGate::execute` calls.
#[derive(Debug)]
pub struct SessionClock {
    anchor: Instant,
    base_unix: u64,
    last: u64,
}

impl SessionClock {
    /// Anchor to the current wall time; subsequent [`now`](Self::now) ticks forward
    /// with `Instant` elapsed time (immune to NTP step-backs during the session).
    pub fn new() -> Self {
        let base_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            anchor: Instant::now(),
            base_unix,
            last: base_unix,
        }
    }

    /// Instant-backed Unix estimate for this session. Always non-decreasing.
    pub fn now(&mut self) -> u64 {
        let t = self.base_unix.saturating_add(self.anchor.elapsed().as_secs());
        if t > self.last {
            self.last = t;
        }
        self.last
    }

    /// Accept a caller-supplied Unix timestamp only if it does not go backward
    /// relative to the previous accepted or derived value in this session.
    pub fn accept(&mut self, supplied: u64) -> Result<u64, ClockError> {
        if supplied < self.last {
            return Err(ClockError::BackwardJump {
                previous: self.last,
                supplied,
            });
        }
        self.last = supplied;
        Ok(supplied)
    }

    pub fn last(&self) -> u64 {
        self.last
    }
}

impl Default for SessionClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn now_is_monotonic_within_session() {
        let mut clock = SessionClock::new();
        let t0 = clock.now();
        thread::sleep(Duration::from_millis(15));
        let t1 = clock.now();
        assert!(t1 >= t0, "session clock must not decrease: {t0} -> {t1}");
    }

    #[test]
    fn accept_rejects_backward_jump() {
        let mut clock = SessionClock::new();
        clock.accept(1_700_000_000).expect("first accept");
        let err = clock.accept(1_699_999_999).unwrap_err();
        assert_eq!(
            err,
            ClockError::BackwardJump {
                previous: 1_700_000_000,
                supplied: 1_699_999_999,
            }
        );
    }

    #[test]
    fn accept_allows_equal_and_forward() {
        let mut clock = SessionClock::new();
        assert_eq!(clock.accept(100).unwrap(), 100);
        assert_eq!(clock.accept(100).unwrap(), 100);
        assert_eq!(clock.accept(101).unwrap(), 101);
    }
}
