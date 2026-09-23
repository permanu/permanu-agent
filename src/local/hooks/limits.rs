//! Per-minute budgets of the webhook intake (agent-protocol.md 7, 11.1):
//! before authentication 30 requests/min per source address and 600/min
//! per server; after it 60 verified deliveries/min per project and 600/min
//! per server. Separate budgets, so forged requests never starve genuine
//! pushes.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

const WINDOW_SECONDS: i64 = 60;
/// Keys tracked at once; a flood of distinct keys beyond this is refused
/// (the server budget still applies to it).
const MAX_KEYS: usize = 4_096;

/// A sliding one-minute window per key plus one for the whole server.
#[derive(Debug)]
pub struct Budget {
    per_key: u32,
    per_server: u32,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    keys: HashMap<String, VecDeque<i64>>,
    server: VecDeque<i64>,
}

fn trim(window: &mut VecDeque<i64>, now: i64) {
    while window.front().is_some_and(|at| now - at >= WINDOW_SECONDS) {
        window.pop_front();
    }
}

impl Budget {
    pub fn new(per_key: u32, per_server: u32) -> Self {
        Self {
            per_key,
            per_server,
            state: Mutex::new(State::default()),
        }
    }

    /// agent-protocol.md 11.1 step 2.
    pub fn pre_auth() -> Self {
        Self::new(30, 600)
    }

    /// agent-protocol.md 11.1 step 5.
    pub fn deploy() -> Self {
        Self::new(60, 600)
    }

    /// Counts one request for `key` at `now`; false when it is over either
    /// budget (and then it is not counted).
    pub fn admit(&self, key: &str, now: i64) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        trim(&mut state.server, now);
        if state.server.len() >= self.per_server as usize {
            return false;
        }
        if !state.keys.contains_key(key) && state.keys.len() >= MAX_KEYS {
            state.keys.retain(|_, window| {
                trim(window, now);
                !window.is_empty()
            });
            if state.keys.len() >= MAX_KEYS {
                return false;
            }
        }
        let window = state.keys.entry(key.to_owned()).or_default();
        trim(window, now);
        if window.len() >= self.per_key as usize {
            return false;
        }
        window.push_back(now);
        state.server.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_gets_its_budget_per_minute() {
        let budget = Budget::pre_auth();
        for _ in 0..30 {
            assert!(budget.admit("203.0.113.9", 1_000));
        }
        assert!(!budget.admit("203.0.113.9", 1_030));
        // Another address still has its own budget.
        assert!(budget.admit("198.51.100.7", 1_030));
        // A minute after the first request the window slides.
        assert!(budget.admit("203.0.113.9", 1_060));
    }

    #[test]
    fn the_server_budget_caps_every_key_together() {
        let budget = Budget::new(1_000, 5);
        for i in 0..5 {
            assert!(budget.admit(&format!("k{i}"), 10));
        }
        assert!(!budget.admit("fresh", 10));
        assert!(budget.admit("fresh", 70));
    }

    #[test]
    fn distinct_keys_are_bounded() {
        let budget = Budget::new(1, u32::MAX);
        for i in 0..MAX_KEYS {
            assert!(budget.admit(&format!("k{i}"), 10));
        }
        assert!(!budget.admit("one-more", 10));
        // Once their windows passed, old keys are dropped.
        assert!(budget.admit("one-more", 100));
    }
}
