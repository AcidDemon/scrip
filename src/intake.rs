use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::config::{Config, LogPastes};
use crate::policy::{
    escalated_minutes, source_key, source_key48, Admit, BanList, RateLimiter, ViolationTracker,
    AGGREGATE_FACTOR,
};
use crate::protocol::{probe_kind, read_paste, ReadOutcome};
use crate::slug::{random_base36, SLUG_LEN};
use crate::store::{RoomOutcome, Store, ROW_OVERHEAD};

pub struct Ctx {
    pub config: Config,
    pub store: Store,
    /// Slug generator. Tests replace it to force collisions and check the retry.
    pub slugs: Box<dyn Fn() -> String + Send + Sync>,
    pub limiter: RateLimiter,
    /// Separate read limiter for GET /{slug} and /raw/{slug}, limiting slug probes.
    pub read_limiter: RateLimiter,
    pub bans: BanList,
    pub conn_sem: Arc<Semaphore>,
    pub per_source: Mutex<HashMap<IpAddr, usize>>,
    pub violations: ViolationTracker,
}

impl Ctx {
    /// Builds the shared limits from config. Tests can override the slug source.
    pub fn new(config: Config, store: Store) -> Ctx {
        Ctx {
            limiter: RateLimiter::new(config.rate_per_minute, config.rate_burst),
            read_limiter: RateLimiter::new(config.read_rate_per_min, config.read_burst),
            bans: BanList::new(),
            conn_sem: Arc::new(Semaphore::new(config.max_conns)),
            per_source: Mutex::new(HashMap::new()),
            violations: ViolationTracker::new(),
            slugs: Box::new(|| random_base36(SLUG_LEN)),
            store,
            config,
        }
    }
}

/// v6 sockets are v6-only so a v4+v6 pair on one port binds on every OS;
/// SO_REUSEADDR so restarts do not trip on TIME_WAIT.
pub fn bind_tcp(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let s = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        s.set_only_v6(true)?;
    }
    s.set_reuse_address(true)?;
    s.bind(&addr.into())?;
    s.listen(1024)?;
    s.set_nonblocking(true)?;
    Ok(s.into())
}

pub async fn accept_loop(
    listener: tokio::net::TcpListener,
    ctx: Arc<Ctx>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    // At capacity, clients see a close with no reply. Log refusals for operators,
    // throttled to avoid one log entry per rejected connection.
    let mut last_full: Option<std::time::Instant> = None;
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            r = listener.accept() => match r {
                Ok((stream, peer)) => {
                    // Global cap. The permit rides into the task; main drains
                    // by reacquiring every permit at shutdown.
                    let permit = match ctx.conn_sem.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            let now = std::time::Instant::now();
                            if last_full.is_none_or(|t| now.duration_since(t) >= Duration::from_secs(10)) {
                                last_full = Some(now);
                                tracing::warn!(
                                    "connection cap ({}) reached, dropping new connections",
                                    ctx.config.max_conns
                                );
                            }
                            continue; // at capacity: drop the connection
                        }
                    };
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        handle(stream, peer.ip(), ctx).await;
                    });
                }
                Err(e) => {
                    // Back off to avoid a busy loop and repeated error logs.
                    tracing::error!("accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

pub struct SourceGuard {
    ctx: Arc<Ctx>,
    key: IpAddr,
}

/// Takes one of this source's `max_conns_per_source` slots, released when the
/// guard drops. Shared by both doors: the cap is per source, not per door, or
/// one door's clients could drain the global pool out from under the other.
pub fn try_source(ctx: &Arc<Ctx>, ip: IpAddr) -> Option<SourceGuard> {
    let key = source_key(ip);
    let mut m = ctx.per_source.lock().unwrap_or_else(|e| e.into_inner());
    let n = m.entry(key).or_insert(0);
    if *n >= ctx.config.max_conns_per_source {
        return None;
    }
    *n += 1;
    Some(SourceGuard {
        ctx: ctx.clone(),
        key,
    })
}

impl Drop for SourceGuard {
    fn drop(&mut self) {
        let mut m = self
            .ctx
            .per_source
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.key);
            }
        }
    }
}

/// Bounds the write-reply-then-drain sequence in `reply_and_close`.
const REPLY_DEADLINE: Duration = Duration::from_secs(2);

/// Lets e2e tests shorten the reply deadline without a separate build.
fn reply_deadline() -> Duration {
    std::env::var("SCRIP_TEST_REPLY_DEADLINE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(REPLY_DEADLINE)
}

/// Write the reply, half-close, then drain what the client is still sending
/// so the kernel sends FIN, not RST. An RST discards the reply in flight.
async fn reply_and_close(stream: &mut TcpStream, msg: &[u8]) {
    // Everything bounded by one deadline: a peer with a zero receive window
    // must not pin this connection's permit on the write either.
    let deadline = tokio::time::Instant::now() + reply_deadline();
    if tokio::time::timeout_at(deadline, stream.write_all(msg))
        .await
        .is_err()
    {
        return; // write stalled out; drop without draining
    }
    let _ = tokio::time::timeout_at(deadline, stream.shutdown()).await;
    let mut scratch = [0u8; 8192];
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut scratch)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(_)) => {}
        }
    }
}

pub fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub enum StoreOutcome {
    Stored {
        slug: String,
        /// Hex token whose SHA-256 the row stores; presenting it authorizes
        /// HTTP DELETE. The TCP door has no reply channel for it and drops
        /// it, so the one-line `nc` reply contract stays intact.
        delete_token: String,
    },
    QuotaFull,
    SourceCapped,
    Error,
}

/// Per-paste knobs from the HTTP door's query string. The TCP door always
/// passes the default: raw bytes until EOF leave no room for options
/// without corrupting pastes that happen to start with an option line.
#[derive(Default, Clone, Copy)]
pub struct PasteOpts {
    /// Requested lifetime in seconds; clamped between one minute and the
    /// configured retention. None = the configured retention.
    pub ttl_secs: Option<i64>,
    /// Destroy on first /raw read.
    pub burn: bool,
}

/// 128-bit hex delete token and the SHA-256 of its hex form (what the
/// client will send back) for the row.
fn delete_token() -> (String, Vec<u8>) {
    use sha2::Digest;
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS RNG unavailable");
    let tok: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    let hash = sha2::Sha256::digest(tok.as_bytes()).to_vec();
    (tok, hash)
}

/// Reply text for both doors when a source is over `max_pastes_per_source`.
pub const SOURCE_CAPPED_MSG: &str = "scrip: paste limit reached for your network\n";

/// Whether an address may ever reach the ban list. Loopback is how the local
/// proxy and every health check appear; the unspecified, link-local and
/// broadcast ranges are never a real remote client. `client_ip` will hand us
/// any of them if the proxy forwards one, and a ban on them is a self-inflicted
/// outage: the list gates every connection and is exported into nftables.
fn bannable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast())
        }
        // is_unicast_link_local is still unstable, so match fe80::/10 directly.
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Tracks rate-limit refusals per source and, past `autoban_threshold`
/// refusals inside `autoban_window_secs`, writes a real ban row with
/// fail2ban-style escalating duration. No-op when autoban is disabled
/// (autoban_minutes == 0). Called from both front doors wherever the rate
/// limiter itself refuses.
pub async fn note_rate_refusal(ctx: &Arc<Ctx>, ip: IpAddr, tier: Admit) {
    if ctx.config.autoban_minutes == 0 {
        return;
    }
    // Charge refusals to the tier that rejected the request. Charging /48
    // refusals to individual /64s would spread strikes across 65,536 counters.
    // Scale the /48 threshold by AGGREGATE_FACTOR to match its larger budget.
    // Select the prefix with the key so an IPv4 tier mismatch cannot pass a
    // /48 prefix to IpNet::new and panic.
    let (key_ip, prefix, threshold) = match (tier, source_key48(ip)) {
        (Admit::RefusedAggregate, Some(k48)) => (
            IpAddr::V6(k48),
            48,
            ctx.config
                .autoban_threshold
                .saturating_mul(AGGREGATE_FACTOR),
        ),
        // IPv4 has no aggregate tier, so a tier mismatch can only mean the
        // source's own bucket refused.
        _ => {
            let key = source_key(ip);
            let prefix = if key.is_ipv4() { 32 } else { 64 };
            (key, prefix, ctx.config.autoban_threshold)
        }
    };
    let net = ipnet::IpNet::new(key_ip, prefix)
        .expect("prefix is 32 for v4, 48 or 64 for v6")
        .trunc();
    // Include the prefix length: source_key48 and source_key return the same
    // address for a /48's zeroth /64. Separate counters prevent /48 strikes
    // from banning that /64 and /64 strikes from resetting the /48 counter.
    let key_str = net.to_string();
    let crossed = ctx.violations.record_refusal(
        &key_str,
        std::time::Instant::now(),
        Duration::from_secs(ctx.config.autoban_window_secs),
        threshold,
    );
    if !crossed {
        return;
    }

    let now = now_epoch();
    let st = ctx.store.clone();
    let key_for_offense = key_str.clone();
    let strikes =
        match tokio::task::spawn_blocking(move || st.record_offense(&key_for_offense, now)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::error!("record_offense failed: {e}");
                return;
            }
            Err(e) => {
                tracing::error!("record_offense failed: task panicked: {e}");
                return;
            }
        };

    // Keep strikes from non-routable sources for diagnosing proxy mistakes,
    // but never ban them. A loopback ban would block the local proxy both
    // here and through the nftables export.
    if !bannable(key_ip) {
        tracing::warn!(
            "{net} crossed the auto-ban threshold at {strikes} strikes; not banning, \
             the address is not a routable remote client"
        );
        return;
    }

    let minutes = escalated_minutes(
        ctx.config.autoban_minutes,
        ctx.config.autoban_factor,
        strikes,
        ctx.config.autoban_max_minutes,
    );
    let mut net = net;
    // With >= 4 sibling /64s in the same /48 already under active auto-bans,
    // ban the covering /48 instead: one routed /48 must not cost 65,536
    // individual /64 rows to contain. Best-effort: a failed count just falls
    // back to banning the /64. Only the /64 tier promotes; the aggregate
    // tier already names the /48, and its strikes are recorded against that
    // /48's own offense row rather than the promoted one.
    // The four-sibling threshold is fixed; make it configurable if needed.
    if let Some(key48) = source_key48(key_ip).filter(|_| prefix != 48) {
        let st = ctx.store.clone();
        let own = net.to_string();
        match tokio::task::spawn_blocking(move || st.count_sibling_autobans48(key48, &own, now))
            .await
        {
            Ok(Ok(n)) if n >= 4 => {
                net = ipnet::IpNet::new(IpAddr::V6(key48), 48).unwrap().trunc();
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::error!("sibling auto-ban count failed: {e}"),
            Err(e) => tracing::error!("sibling auto-ban count failed: task panicked: {e}"),
        }
    }
    let until = now + minutes as i64 * 60;

    // extend_ban, not add_ban: an auto-ban must never shorten an existing
    // (possibly operator-set, possibly permanent) ban for the same net.
    let st = ctx.store.clone();
    let cidr_str = net.to_string();
    let for_db = cidr_str.clone();
    match tokio::task::spawn_blocking(move || {
        st.extend_ban(&for_db, Some("auto: rate abuse"), Some(until))
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::error!("auto-ban extend_ban failed: {e}");
            return;
        }
        Err(e) => {
            tracing::error!("auto-ban extend_ban failed: task panicked: {e}");
            return;
        }
    }
    ctx.bans.insert(net, Some(until));
    tracing::warn!("auto-ban {cidr_str}: strikes={strikes} minutes={minutes}");
}

/// How a source is named in a log line that is not the stored-paste line:
/// the address under "full", and the coarse key otherwise, so journald
/// keeps no more about an author than `log_pastes` allows. Quota pressure
/// and refusals still need something to correlate on, so "off" degrades to
/// the /64 or /32 rather than to nothing.
fn log_source(mode: LogPastes, ip: IpAddr) -> String {
    match mode {
        LogPastes::Full => ip.to_string(),
        _ => source_key(ip).to_string(),
    }
}

/// Logs stored pastes according to `log_pastes` for both upload paths.
fn stored_log_line(mode: LogPastes, slug: &str, ip: IpAddr, size: usize) -> String {
    match mode {
        LogPastes::Full => format!("stored paste as {slug} from {ip}"),
        LogPastes::Url => format!("stored paste as {slug}"),
        LogPastes::Off => format!("stored a paste of {size} bytes"),
    }
}

/// Shared TCP and HTTP write path: check quota, then insert, regenerating
/// the slug once on conflict.
pub async fn store_paste(
    ctx: &Arc<Ctx>,
    ip: IpAddr,
    body: Arc<Vec<u8>>,
    opts: PasteOpts,
) -> StoreOutcome {
    if ctx.config.max_pastes_per_source > 0 {
        let key = source_key(ip).to_string();
        let st = ctx.store.clone();
        match tokio::task::spawn_blocking(move || st.count_by_source_key(&key)).await {
            Ok(Ok(n)) if n >= ctx.config.max_pastes_per_source => {
                return StoreOutcome::SourceCapped
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                tracing::error!("source cap query failed: {e}");
                return StoreOutcome::Error;
            }
            Err(e) => {
                tracing::error!("source cap query failed: task panicked: {e}");
                return StoreOutcome::Error;
            }
        }
        // Aggregate tier: one routed /48 must not multiply the per-/64 cap
        // 65,536x by rotating /64s.
        if let Some(key48) = source_key48(ip) {
            let cap48 = ctx
                .config
                .max_pastes_per_source
                .saturating_mul(AGGREGATE_FACTOR);
            let st = ctx.store.clone();
            match tokio::task::spawn_blocking(move || st.count_by_source_key48(key48)).await {
                Ok(Ok(n)) if n >= cap48 => return StoreOutcome::SourceCapped,
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    tracing::error!("/48 source cap query failed: {e}");
                    return StoreOutcome::Error;
                }
                Err(e) => {
                    tracing::error!("/48 source cap query failed: task panicked: {e}");
                    return StoreOutcome::Error;
                }
            }
        }
    }
    // Reject pastes that cannot fit even in an empty store. Otherwise make_room
    // can evict expired rows and live pastes older than half their retention.
    // If that cannot free enough space, refuse the upload and keep fresh pastes.
    let seal_overhead = if ctx.config.encrypt_at_rest {
        crate::crypto::SEAL_OVERHEAD
    } else {
        0
    };
    let need = body.len() as u64 + seal_overhead + ROW_OVERHEAD;
    if need > ctx.config.quota_bytes {
        tracing::error!(
            "paste of {} bytes cannot fit the quota at all, refusing paste from {}",
            body.len(),
            log_source(ctx.config.log_mode(), ip)
        );
        return StoreOutcome::QuotaFull;
    }
    // Make-room-then-insert races by at most one in-flight paste per
    // connection. Bounded overshoot beats a transaction on every paste.
    let st = ctx.store.clone();
    let quota = ctx.config.quota_bytes;
    let retention_days = ctx.config.retention_days;
    match tokio::task::spawn_blocking(move || st.make_room(need, quota, retention_days)).await {
        Ok(Ok(RoomOutcome::Fits { evicted: 0, .. })) => {}
        Ok(Ok(RoomOutcome::Fits { evicted, bytes })) => {
            // warn, not info: an attacker-inducible destruction event that
            // operators must see.
            tracing::warn!(
                "quota pressure: evicted {evicted} oldest pastes ({bytes} bytes) for {}",
                log_source(ctx.config.log_mode(), ip)
            );
        }
        Ok(Ok(RoomOutcome::Full)) => {
            tracing::warn!(
                "quota full and nothing old enough to evict, refusing paste from {}",
                log_source(ctx.config.log_mode(), ip)
            );
            return StoreOutcome::QuotaFull;
        }
        Ok(Err(e)) => {
            tracing::error!("quota eviction failed: {e}");
            return StoreOutcome::Error;
        }
        Err(e) => {
            tracing::error!("quota eviction failed: task panicked: {e}");
            return StoreOutcome::Error;
        }
    }
    let created = now_epoch();
    // Clamp here, in the single write path, so both doors agree: never past
    // the configured retention, never under a minute (a typoed ttl must not
    // create a paste that is dead before its URL prints).
    let max_ttl = ctx.config.retention_days as i64 * 86_400;
    let ttl = opts
        .ttl_secs
        .unwrap_or(max_ttl)
        .min(max_ttl)
        .max(60.min(max_ttl));
    let expires = created + ttl;
    let (token, token_hash) = delete_token();
    for attempt in 0..2 {
        // Fresh material each attempt: on a conflict the whole identity is
        // regenerated, plain slug and encryption token alike.
        let (url_slug, db_slug, stored) = if ctx.config.encrypt_at_rest {
            // The URL token is the key; the row keeps only its hashed id
            // and the sealed body. Log lines below carry the id, never the
            // token: journald must not hold what decrypts the database.
            let t = crate::crypto::token();
            let id = crate::crypto::token_id(&t);
            let sealed = Arc::new(crate::crypto::seal(&t, &body));
            (t, id, sealed)
        } else {
            let s = (ctx.slugs)();
            (s.clone(), s, body.clone())
        };
        let st = ctx.store.clone();
        let (s, b, ipstr, th) = (
            db_slug.clone(),
            stored.clone(),
            ip.to_string(),
            token_hash.clone(),
        );
        match tokio::task::spawn_blocking(move || {
            st.insert_paste_opts(&s, &b[..], &ipstr, created, expires, opts.burn, Some(&th))
        })
        .await
        {
            Ok(Ok(true)) => {
                tracing::info!(
                    "{}",
                    stored_log_line(ctx.config.log_mode(), &db_slug, ip, stored.len())
                );
                return StoreOutcome::Stored {
                    slug: url_slug,
                    delete_token: token,
                };
            }
            Ok(Ok(false)) if attempt == 0 => {}
            Ok(Ok(false)) => {
                tracing::error!("slug conflict twice in a row, refusing paste");
                return StoreOutcome::Error;
            }
            Ok(Err(e)) => {
                tracing::error!("insert failed: {e}");
                return StoreOutcome::Error;
            }
            Err(e) => {
                tracing::error!("insert failed: task panicked: {e}");
                return StoreOutcome::Error;
            }
        }
    }
    StoreOutcome::Error
}

async fn handle(mut stream: TcpStream, ip: IpAddr, ctx: Arc<Ctx>) {
    // Policy order: ban, rate, size (inside the read), probe, quota.
    if ctx.bans.is_banned(ip, now_epoch()) {
        return; // banned sources get silence, not a protocol
    }
    let _guard = match try_source(&ctx, ip) {
        Some(g) => g,
        None => {
            reply_and_close(&mut stream, b"scrip: too many connections\n").await;
            return;
        }
    };
    let admit = ctx.limiter.try_acquire(ip, std::time::Instant::now());
    if admit.refused() {
        note_rate_refusal(&ctx, ip, admit).await;
        reply_and_close(&mut stream, b"scrip: rate limited, try again later\n").await;
        return;
    }

    let cap = ctx.config.max_paste_bytes as usize;
    let outcome = match read_paste(
        &mut stream,
        cap,
        Duration::from_secs(ctx.config.idle_timeout_secs),
        Duration::from_secs(ctx.config.total_deadline_secs),
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::debug!("read from {}: {e}", log_source(ctx.config.log_mode(), ip));
            return;
        }
    };

    let body = match outcome {
        ReadOutcome::Empty => return,
        ReadOutcome::TooLarge => {
            let msg = format!("scrip: paste too large (max {cap} bytes)\n");
            reply_and_close(&mut stream, msg.as_bytes()).await;
            return;
        }
        // Blank lines are what scanners send to make a quiet service talk.
        // Like an empty read, they store nothing and get no reply.
        ReadOutcome::Complete(b) if b.trim_ascii().is_empty() => return,
        ReadOutcome::Complete(b) => Arc::new(b),
    };

    if let Some(kind) = probe_kind(&body) {
        tracing::info!(
            "refused {kind} probe from {}",
            log_source(ctx.config.log_mode(), ip)
        );
        let msg = format!("scrip: refused {kind} probe; prepend a line to paste it anyway\n");
        reply_and_close(&mut stream, msg.as_bytes()).await;
        return;
    }

    match store_paste(&ctx, ip, body, PasteOpts::default()).await {
        StoreOutcome::Stored { slug, .. } => {
            let reply = format!("{}/{}\n", ctx.config.base_url, slug);
            reply_and_close(&mut stream, reply.as_bytes()).await;
        }
        StoreOutcome::QuotaFull => reply_and_close(&mut stream, b"scrip: storage full\n").await,
        StoreOutcome::SourceCapped => {
            reply_and_close(&mut stream, SOURCE_CAPPED_MSG.as_bytes()).await
        }
        StoreOutcome::Error => reply_and_close(&mut stream, b"scrip: internal error\n").await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_source_follows_the_knob_too() {
        let v4: IpAddr = "203.0.113.5".parse().unwrap();
        let v6: IpAddr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        // "full" is the only mode that may name the exact address
        assert_eq!(log_source(LogPastes::Full, v4), "203.0.113.5");
        assert_eq!(log_source(LogPastes::Full, v6), "2001:db8:1:2:3:4:5:6");
        // the others degrade to the key the limits are enforced on, which
        // is still correlatable but is not the author's address
        assert_eq!(log_source(LogPastes::Url, v6), "2001:db8:1:2::");
        assert_eq!(log_source(LogPastes::Off, v6), "2001:db8:1:2::");
        for mode in [LogPastes::Url, LogPastes::Off] {
            assert!(
                !log_source(mode, v6).contains("3:4:5:6"),
                "{mode:?} must not log the host part of a v6 address"
            );
        }
    }

    #[test]
    fn stored_log_line_shapes_follow_the_knob() {
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        assert_eq!(
            stored_log_line(LogPastes::Full, "abcd1234", ip, 7),
            "stored paste as abcd1234 from 203.0.113.5"
        );
        let url = stored_log_line(LogPastes::Url, "abcd1234", ip, 7);
        assert_eq!(url, "stored paste as abcd1234");
        assert!(!url.contains("203.0.113.5"), "url mode must not log the IP");
        let off = stored_log_line(LogPastes::Off, "abcd1234", ip, 7);
        assert_eq!(off, "stored a paste of 7 bytes");
        assert!(!off.contains("abcd1234"), "off mode must not log the slug");
    }
}
