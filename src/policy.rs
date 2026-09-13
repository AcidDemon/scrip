use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use ipnet::IpNet;

/// Rate-limit key: the address for IPv4, the /64 for IPv6. Never /128, since
/// a residential IPv6 customer holds 2^64 addresses. Canonicalized first: an
/// IPv4-mapped ::ffff:a.b.c.d must key as its v4 address, or every mapped v4
/// client behind a proxy shares the one truncated ::/64 key.
pub fn source_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        v4 @ IpAddr::V4(_) => v4,
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

/// Multiplier for the /48 tier's rate, burst, live-paste cap, and auto-ban
/// threshold relative to a single /64.
// Fixed across all limits; make configurable if legitimate /48 traffic needs it.
pub const AGGREGATE_FACTOR: u32 = 8;

/// The /48 containing an IPv6 source, for the aggregate enforcement tier: a
/// routed /48 is 65,536 /64 identities, so per-/64 controls alone would be
/// trivially rotated around. None for IPv4, which has no aggregate tier.
pub fn source_key48(ip: IpAddr) -> Option<Ipv6Addr> {
    match ip.to_canonical() {
        IpAddr::V4(_) => None,
        IpAddr::V6(v6) => {
            let s = v6.segments();
            Some(Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0))
        }
    }
}

/// Which tier accepted or refused the request. Auto-ban strikes belong to
/// the tier that refused: charging /48 refusals to individual /64s could
/// spread an attack across 65,536 counters without any reaching the threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    Ok,
    RefusedSource,
    RefusedAggregate,
}

impl Admit {
    pub fn is_ok(self) -> bool {
        matches!(self, Admit::Ok)
    }

    pub fn refused(self) -> bool {
        !self.is_ok()
    }
}

pub struct BanList {
    nets: RwLock<Vec<(IpNet, Option<i64>)>>,
}

impl BanList {
    pub fn new() -> BanList {
        BanList {
            nets: RwLock::new(Vec::new()),
        }
    }

    pub fn replace(&self, nets: Vec<(IpNet, Option<i64>)>) {
        *self.nets.write().unwrap_or_else(|e| e.into_inner()) = nets;
    }

    /// Applies a fresh ban immediately, without waiting for the next reload.
    /// Updates an existing entry for the same net instead of duplicating it,
    /// and never shortens: a permanent entry (until None) stays permanent
    /// and a timed one only ever grows, mirroring `Store::extend_ban` so the
    /// in-memory list can't undercut the DB row between reloads.
    pub fn insert(&self, net: IpNet, until: Option<i64>) {
        let mut nets = self.nets.write().unwrap_or_else(|e| e.into_inner());
        match nets.iter_mut().find(|(n, _)| *n == net) {
            Some(entry) => {
                entry.1 = match (entry.1, until) {
                    (None, _) | (_, None) => None,
                    (Some(a), Some(b)) => Some(a.max(b)),
                }
            }
            None => nets.push((net, until)),
        }
    }

    // Linear scan. Fine to ~10k rows; a prefix trie if the list grows past that.
    pub fn is_banned(&self, ip: IpAddr, now_epoch: i64) -> bool {
        self.nets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|(net, until)| net.contains(&ip) && until.is_none_or(|u| u > now_epoch))
    }
}

impl Default for BanList {
    fn default() -> Self {
        Self::new()
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    /// Aggregate buckets keyed by the /48 (see `source_key48`), IPv6 only.
    /// A separate map: a /64 key with a zero fourth group would otherwise
    /// collide with its own /48 key.
    buckets48: Mutex<HashMap<IpAddr, Bucket>>,
    rate_per_sec: f64,
    burst: f64,
}

impl RateLimiter {
    pub fn new(per_minute: f64, burst: f64) -> RateLimiter {
        RateLimiter {
            buckets: Mutex::new(HashMap::new()),
            buckets48: Mutex::new(HashMap::new()),
            rate_per_sec: per_minute / 60.0,
            burst,
        }
    }

    fn take_token(
        buckets: &Mutex<HashMap<IpAddr, Bucket>>,
        key: IpAddr,
        now: Instant,
        rate_per_sec: f64,
        burst: f64,
    ) -> bool {
        let mut m = buckets.lock().unwrap_or_else(|e| e.into_inner());
        let b = m.entry(key).or_insert(Bucket {
            tokens: burst,
            last: now,
        });
        let dt = now.saturating_duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + dt * rate_per_sec).min(burst);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// The clock is a parameter so tests never sleep. An IPv6 request must
    /// pass both its /64 bucket and the covering /48's aggregate bucket, so
    /// one routed /48 cannot rotate through 65,536 fresh /64 budgets.
    pub fn try_acquire(&self, ip: IpAddr, now: Instant) -> Admit {
        if !Self::take_token(
            &self.buckets,
            source_key(ip),
            now,
            self.rate_per_sec,
            self.burst,
        ) {
            return Admit::RefusedSource;
        }
        match source_key48(ip) {
            Some(k48) => {
                if Self::take_token(
                    &self.buckets48,
                    IpAddr::V6(k48),
                    now,
                    self.rate_per_sec * f64::from(AGGREGATE_FACTOR),
                    self.burst * f64::from(AGGREGATE_FACTOR),
                ) {
                    Admit::Ok
                } else {
                    Admit::RefusedAggregate
                }
            }
            None => Admit::Ok,
        }
    }

    pub fn evict_idle(&self, now: Instant, idle: Duration) {
        self.buckets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, b| now.saturating_duration_since(b.last) < idle);
        self.buckets48
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, b| now.saturating_duration_since(b.last) < idle);
    }

    #[cfg(test)]
    pub fn bucket_count(&self) -> usize {
        self.buckets.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    #[cfg(test)]
    pub fn bucket48_count(&self) -> usize {
        self.buckets48
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    #[cfg(test)]
    pub fn tokens_for_test(&self, ip: IpAddr, now: Instant) -> f64 {
        let key = source_key(ip);
        let m = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        m.get(&key).map_or(self.burst, |b| {
            (b.tokens + now.saturating_duration_since(b.last).as_secs_f64() * self.rate_per_sec)
                .min(self.burst)
        })
    }
}

/// Counts rate-limit refusals per source within a rolling window.
///
/// Keyed by CIDR string, not by address: `source_key` and `source_key48`
/// return the same `Ipv6Addr` for everything in a /48's zeroth /64. Sharing
/// a counter would let /48 strikes ban that /64 and let /64 strikes reset
/// the /48 counter. `RateLimiter` separates these keys into two maps.
pub struct ViolationTracker {
    state: Mutex<HashMap<String, (u32, Instant)>>,
}

impl ViolationTracker {
    pub fn new() -> ViolationTracker {
        ViolationTracker {
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true when `threshold` refusals landed inside `window`. The
    /// count resets to 0 both when the window has expired and right after a
    /// trip, so one crossing yields exactly one ban per burst.
    pub fn record_refusal(
        &self,
        key: &str,
        now: Instant,
        window: Duration,
        threshold: u32,
    ) -> bool {
        let mut m = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let entry = m.entry(key.to_string()).or_insert((0, now));
        if now.saturating_duration_since(entry.1) >= window {
            entry.0 = 0;
            entry.1 = now;
        }
        entry.0 += 1;
        if entry.0 >= threshold {
            entry.0 = 0;
            entry.1 = now;
            true
        } else {
            false
        }
    }

    /// Drops entries whose window has gone stale, same shape as
    /// `RateLimiter::evict_idle`. Without this a refusal from every distinct
    /// source key leaves a permanent map entry.
    pub fn evict_idle(&self, now: Instant, idle: Duration) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (_, last)| now.saturating_duration_since(*last) < idle);
    }

    #[cfg(test)]
    pub fn entry_count(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Default for ViolationTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// fail2ban-style escalation: each repeat strike multiplies the ban duration
/// by `factor`, capped at `max`. `strikes` is 1-based (the first strike uses
/// `base` unscaled).
pub fn escalated_minutes(base: u64, factor: f64, strikes: u32, max: u64) -> u64 {
    // Clamp the exponent: an absurd strike count must saturate, not wrap
    // `as i32` into a negative power.
    let exponent = strikes.saturating_sub(1).min(i32::MAX as u32) as i32;
    let scaled = base as f64 * factor.powi(exponent);
    (scaled.round().max(1.0) as u64).min(max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, Instant};

    #[test]
    fn v4_keys_are_the_address_v6_keys_are_the_64() {
        let v4: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(source_key(v4), v4);
        let a: IpAddr = "2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:1111:2222:3333:4444".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(source_key(a), source_key(b)); // same /64 shares a key
        assert_ne!(source_key(a), source_key(c)); // different /64 does not
    }

    #[test]
    fn mapped_v4_keys_as_the_v4_address() {
        let mapped: IpAddr = "::ffff:1.2.3.4".parse().unwrap();
        assert_eq!(source_key(mapped), "1.2.3.4".parse::<IpAddr>().unwrap());
        // and never gets a v6 aggregate tier
        assert_eq!(source_key48(mapped), None);
    }

    #[test]
    fn source_key48_shares_across_64s_and_splits_across_48s() {
        let a: IpAddr = "2001:db8:1:2::7".parse().unwrap();
        let b: IpAddr = "2001:db8:1:ffff::9".parse().unwrap();
        let c: IpAddr = "2001:db8:2::7".parse().unwrap();
        assert_eq!(source_key48(a), source_key48(b)); // same /48 shares a key
        assert_ne!(source_key48(a), source_key48(c)); // different /48 does not
    }

    #[test]
    fn sixty_fours_in_one_48_share_the_aggregate_bucket() {
        let rl = RateLimiter::new(60.0, 1.0); // /64 burst 1 => /48 burst 8
        let t0 = Instant::now();
        // 8 distinct /64s inside 2001:db8:1::/48: each passes its own fresh
        // /64 bucket while draining one shared /48 token.
        for i in 0..8u16 {
            let ip: IpAddr = format!("2001:db8:1:{i:x}::7").parse().unwrap();
            assert!(rl.try_acquire(ip, t0).is_ok(), "/64 number {i} should pass");
        }
        // the 9th /64 has a fresh /64 bucket, but the /48 budget is spent
        assert!(rl
            .try_acquire("2001:db8:1:8::7".parse().unwrap(), t0)
            .refused());
        // a different /48 is unaffected
        assert!(rl.try_acquire("2001:db8:2::7".parse().unwrap(), t0).is_ok());
    }

    #[test]
    fn banlist_matches_containment_and_expiry() {
        let bl = BanList::new();
        bl.replace(vec![
            ("203.0.113.0/24".parse().unwrap(), None),
            ("2001:db8::/32".parse().unwrap(), Some(1000)),
        ]);
        assert!(bl.is_banned("203.0.113.9".parse().unwrap(), 0));
        assert!(!bl.is_banned("203.0.114.9".parse().unwrap(), 0));
        assert!(bl.is_banned("2001:db8:ffff::1".parse().unwrap(), 999)); // not yet expired
        assert!(!bl.is_banned("2001:db8:ffff::1".parse().unwrap(), 1000)); // expired
    }

    #[test]
    fn bucket_allows_burst_then_refuses_then_refills() {
        let rl = RateLimiter::new(60.0, 2.0); // 1 token per second, burst 2
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let t0 = Instant::now();
        assert!(rl.try_acquire(ip, t0).is_ok());
        assert!(rl.try_acquire(ip, t0).is_ok());
        assert!(rl.try_acquire(ip, t0).refused()); // burst exhausted
        assert!(rl.try_acquire(ip, t0 + Duration::from_secs(1)).is_ok()); // one token back
        assert!(rl.try_acquire(ip, t0 + Duration::from_secs(1)).refused());
    }

    #[test]
    fn two_addresses_in_one_64_share_a_bucket() {
        let rl = RateLimiter::new(60.0, 1.0);
        let t0 = Instant::now();
        assert!(rl.try_acquire("2001:db8::a".parse().unwrap(), t0).is_ok());
        assert!(rl.try_acquire("2001:db8::b".parse().unwrap(), t0).refused()); // same /64: refused
        assert!(rl.try_acquire("2001:db9::a".parse().unwrap(), t0).is_ok()); // different /64: own bucket
    }

    #[test]
    fn violation_tracker_trips_at_threshold() {
        let vt = ViolationTracker::new();
        let key = "192.0.2.1/32";
        let t0 = Instant::now();
        let window = Duration::from_secs(60);
        assert!(!vt.record_refusal(key, t0, window, 3));
        assert!(!vt.record_refusal(key, t0, window, 3));
        assert!(vt.record_refusal(key, t0, window, 3)); // 3rd refusal trips it
    }

    /// A /48 and its zeroth /64 render to the same address but different
    /// CIDRs; keyed by address they would share one counter, so the /48's
    /// strikes would ban that /64 and its trips would reset the /48's count.
    #[test]
    fn violation_tracker_separates_a_48_from_its_zeroth_64() {
        let vt = ViolationTracker::new();
        let t0 = Instant::now();
        let window = Duration::from_secs(60);
        let agg = "2001:db8:7::/48";
        let sixtyfour = "2001:db8:7::/64";
        assert_eq!(
            source_key("2001:db8:7:0::9".parse().unwrap()).to_string(),
            IpAddr::V6(source_key48("2001:db8:7:aaaa::1".parse().unwrap()).unwrap()).to_string(),
            "precondition: the two tiers render identically as bare addresses"
        );
        // three strikes on the /48 must leave the /64 untouched
        for _ in 0..3 {
            assert!(!vt.record_refusal(agg, t0, window, 4));
        }
        assert!(!vt.record_refusal(sixtyfour, t0, window, 2));
        assert!(vt.record_refusal(sixtyfour, t0, window, 2)); // its own 2nd
        assert!(vt.record_refusal(agg, t0, window, 4)); // the /48's own 4th
    }

    #[test]
    fn violation_tracker_resets_after_window_expires() {
        let vt = ViolationTracker::new();
        let key = "192.0.2.2/32";
        let t0 = Instant::now();
        let window = Duration::from_secs(60);
        assert!(!vt.record_refusal(key, t0, window, 3));
        assert!(!vt.record_refusal(key, t0, window, 3));
        // window elapsed: count must restart from 0, not carry the 2 over
        let t1 = t0 + Duration::from_secs(61);
        assert!(!vt.record_refusal(key, t1, window, 3));
        assert!(!vt.record_refusal(key, t1, window, 3));
        assert!(vt.record_refusal(key, t1, window, 3));
    }

    #[test]
    fn violation_tracker_resets_count_after_tripping() {
        let vt = ViolationTracker::new();
        let key = "192.0.2.3/32";
        let t0 = Instant::now();
        let window = Duration::from_secs(60);
        assert!(!vt.record_refusal(key, t0, window, 2));
        assert!(vt.record_refusal(key, t0, window, 2)); // trips, resets to 0
                                                        // one ban per burst: needs another full run of refusals to trip again
        assert!(!vt.record_refusal(key, t0, window, 2));
        assert!(vt.record_refusal(key, t0, window, 2));
    }

    #[test]
    fn escalation_math_matches_fail2ban_style_doubling() {
        assert_eq!(escalated_minutes(30, 2.0, 1, 1440), 30);
        assert_eq!(escalated_minutes(30, 2.0, 2, 1440), 60);
        assert_eq!(escalated_minutes(30, 2.0, 3, 1440), 120);
        assert_eq!(escalated_minutes(30, 2.0, 20, 1440), 1440); // capped
        assert_eq!(escalated_minutes(30, 1.0, 5, 1440), 30); // flat factor
    }

    #[test]
    fn banlist_insert_applies_immediately() {
        let bl = BanList::new();
        assert!(!bl.is_banned("203.0.113.1".parse().unwrap(), 0));
        bl.insert("203.0.113.0/24".parse().unwrap(), None);
        assert!(bl.is_banned("203.0.113.1".parse().unwrap(), 0));
    }

    #[test]
    fn banlist_insert_updates_rather_than_duplicates_the_same_net() {
        let bl = BanList::new();
        let net: IpNet = "203.0.113.0/24".parse().unwrap();
        bl.insert(net, Some(100));
        bl.insert(net, Some(200)); // repeat strike: same net, longer until
        assert!(bl.is_banned("203.0.113.1".parse().unwrap(), 150));
        // if it had duplicated instead of updated, is_banned would still be
        // true here off the stale first row; assert there is exactly one row
        let nets = bl.nets.read().unwrap();
        assert_eq!(nets.len(), 1);
        assert_eq!(nets[0], (net, Some(200)));
    }

    #[test]
    fn banlist_insert_never_shortens_an_existing_ban() {
        let net: IpNet = "203.0.113.0/24".parse().unwrap();
        // permanent stays permanent through an auto-ban strike
        let bl = BanList::new();
        bl.insert(net, None);
        bl.insert(net, Some(100));
        assert_eq!(bl.nets.read().unwrap()[0], (net, None));
        // a shorter until never undercuts a longer one
        let bl = BanList::new();
        bl.insert(net, Some(200));
        bl.insert(net, Some(100));
        assert_eq!(bl.nets.read().unwrap()[0], (net, Some(200)));
        // a permanent strike upgrades a timed ban
        let bl = BanList::new();
        bl.insert(net, Some(200));
        bl.insert(net, None);
        assert_eq!(bl.nets.read().unwrap()[0], (net, None));
    }

    #[test]
    fn violation_tracker_evicts_stale_entries_but_keeps_fresh_ones() {
        let vt = ViolationTracker::new();
        let t0 = Instant::now();
        let window = Duration::from_secs(60);
        vt.record_refusal("192.0.2.1/32", t0, window, 100);
        vt.record_refusal("192.0.2.2/32", t0 + Duration::from_secs(600), window, 100);
        assert_eq!(vt.entry_count(), 2);
        vt.evict_idle(t0 + Duration::from_secs(600), Duration::from_secs(300));
        assert_eq!(vt.entry_count(), 1); // only the fresh (192.0.2.2) entry survives
    }

    #[test]
    fn evict_drops_idle_buckets() {
        let rl = RateLimiter::new(60.0, 1.0);
        let t0 = Instant::now();
        let _ = rl.try_acquire("192.0.2.1".parse().unwrap(), t0);
        let _ = rl.try_acquire("2001:db8::1".parse().unwrap(), t0); // fills a /48 bucket too
        rl.evict_idle(t0 + Duration::from_secs(600), Duration::from_secs(300));
        assert_eq!(rl.bucket_count(), 0);
        assert_eq!(rl.bucket48_count(), 0);
    }

    /// Reference containment: mask both sides, compare. Guards ipnet usage
    /// (and our key function) against silent semantic drift.
    fn contains_ref(net: &ipnet::IpNet, ip: &IpAddr) -> bool {
        match (net, ip) {
            (ipnet::IpNet::V4(n), IpAddr::V4(a)) => {
                let p = n.prefix_len();
                let m = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                (u32::from(n.addr()) & m) == (u32::from(*a) & m)
            }
            (ipnet::IpNet::V6(n), IpAddr::V6(a)) => {
                let p = n.prefix_len();
                let m = if p == 0 { 0 } else { u128::MAX << (128 - p) };
                (u128::from(n.addr()) & m) == (u128::from(*a) & m)
            }
            _ => false,
        }
    }

    proptest! {
        #[test]
        fn cidr_agrees_with_reference_v4(addr: u32, net: u32, prefix in 0u8..=32) {
            let net = ipnet::IpNet::V4(ipnet::Ipv4Net::new(Ipv4Addr::from(net), prefix).unwrap());
            let ip = IpAddr::V4(Ipv4Addr::from(addr));
            prop_assert_eq!(net.contains(&ip), contains_ref(&net, &ip));
        }

        #[test]
        fn cidr_agrees_with_reference_v6(addr: u128, net: u128, prefix in 0u8..=128) {
            let net = ipnet::IpNet::V6(ipnet::Ipv6Net::new(Ipv6Addr::from(net), prefix).unwrap());
            let ip = IpAddr::V6(Ipv6Addr::from(addr));
            prop_assert_eq!(net.contains(&ip), contains_ref(&net, &ip));
        }

        #[test]
        fn bucket_never_exceeds_burst_or_goes_negative(
            steps in proptest::collection::vec((0u64..5000, proptest::bool::ANY), 1..100),
            burst in 1.0f64..10.0,
        ) {
            let rl = RateLimiter::new(60.0, burst);
            let ip: IpAddr = "192.0.2.7".parse().unwrap();
            let mut now = Instant::now();
            for (ms, acquire) in steps {
                now += Duration::from_millis(ms);
                if acquire {
                    let _ = rl.try_acquire(ip, now);
                }
                let t = rl.tokens_for_test(ip, now);
                prop_assert!((0.0..=burst).contains(&t), "tokens {t} outside [0, {burst}]");
            }
        }
    }
}
