use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use scrip::cli_util::parse_duration_secs;
use scrip::config::Config;
use scrip::intake::{self, Ctx};
use scrip::store::Store;

#[derive(Parser)]
#[command(name = "scrip", version, about = "command line pastebin")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the server
    Run(RunArgs),
    /// Manage the ban list
    Ban(BanArgs),
    /// Delete one paste (takedown)
    Rm(RmArgs),
    /// Sweep expired pastes now
    Gc(DbArgs),
}

#[derive(Args)]
struct RunArgs {
    /// Config file (default: /etc/scrip/scrip.toml when present)
    #[arg(long)]
    config: Option<PathBuf>,
    /// Override db_path
    #[arg(long)]
    db: Option<PathBuf>,
    /// Override base_url
    #[arg(long = "base-url")]
    base_url: Option<String>,
    /// Override listen_tcp (repeatable)
    #[arg(long = "listen-tcp")]
    listen_tcp: Vec<SocketAddr>,
}

#[derive(Args)]
struct DbArgs {
    /// Config file (default: /etc/scrip/scrip.toml when present)
    #[arg(long)]
    config: Option<PathBuf>,
    /// Override db_path
    #[arg(long)]
    db: Option<PathBuf>,
}

#[derive(Args)]
struct BanArgs {
    #[command(subcommand)]
    cmd: BanCmd,
}

#[derive(Subcommand)]
enum BanCmd {
    /// Ban a CIDR, optionally purging its pastes in the same transaction
    Add {
        cidr: ipnet::IpNet,
        #[arg(long)]
        reason: Option<String>,
        /// Ban duration like 30d, 12h, 45m (default: permanent)
        #[arg(long = "for")]
        duration: Option<String>,
        /// Also delete every paste from inside the CIDR, atomically
        #[arg(long)]
        purge: bool,
        #[command(flatten)]
        db: DbArgs,
    },
    /// Remove a ban
    Rm {
        cidr: String,
        #[command(flatten)]
        db: DbArgs,
    },
    /// List bans
    List {
        #[command(flatten)]
        db: DbArgs,
    },
    /// Emit the ban list as nftables add-element lines
    Export {
        #[command(flatten)]
        db: DbArgs,
    },
}

#[derive(Args)]
struct RmArgs {
    slug: String,
    #[command(flatten)]
    db: DbArgs,
}

/// Where a CLI verb's database lives: the config file's `db_path`, overridden
/// by `--db`.
fn store_path(db: &DbArgs) -> Result<std::path::PathBuf, String> {
    let mut config = Config::load(db.config.as_deref())?;
    if let Some(p) = &db.db {
        config.db_path = p.clone();
    }
    Ok(config.db_path)
}

fn open_store(db: &DbArgs) -> Result<Store, String> {
    let path = store_path(db)?;
    // Connection::open has CREATE semantics; without this check every verb
    // silently "succeeds" against a fresh empty DB on a wrong/typo'd path.
    if !path.exists() {
        return Err(format!("no database at {}", path.display()));
    }
    Store::open(&path).map_err(|e| format!("open db {}: {e}", path.display()))
}

/// The largest per-element timeout nftables accepts, in seconds (it prints it
/// back as 1157d9h46m39s). Anything above is `Error: value too large`.
const NFT_MAX_TIMEOUT_SECS: i64 = 99_999_999;

fn ban_cmd(cmd: BanCmd) -> Result<(), String> {
    match cmd {
        BanCmd::Add {
            cidr,
            reason,
            duration,
            purge,
            db,
        } => {
            let store = open_store(&db)?;
            let until = duration
                .map(|d| {
                    parse_duration_secs(&d).and_then(|secs| {
                        scrip::intake::now_epoch()
                            .checked_add(secs)
                            .ok_or_else(|| format!("duration too large: {d}"))
                    })
                })
                .transpose()?;
            if purge {
                let purged = store
                    .add_ban_with_purge(&cidr, reason.as_deref(), until)
                    .map_err(|e| format!("ban add: {e}"))?;
                if purged > 0 {
                    // Takedown: push the secure_delete-zeroed pages out of
                    // the WAL and freelist so the purged bytes leave disk.
                    store.scrub().map_err(|e| format!("ban add scrub: {e}"))?;
                }
                println!("banned {cidr} (purged {purged} pastes)");
            } else {
                store
                    .add_ban(&cidr.trunc().to_string(), reason.as_deref(), until)
                    .map_err(|e| format!("ban add: {e}"))?;
                println!("banned {cidr}");
            }
            Ok(())
        }
        BanCmd::Rm { cidr, db } => {
            let store = open_store(&db)?;
            // Normalize so equivalent spellings (IPv6 compression, etc.) match
            // what add_ban stored; fall back to the raw string so unparseable
            // legacy rows stay removable.
            let key = cidr
                .parse::<ipnet::IpNet>()
                .map(|n| n.trunc().to_string())
                .unwrap_or(cidr);
            if store.remove_ban(&key).map_err(|e| format!("ban rm: {e}"))? {
                println!("removed {key}");
                Ok(())
            } else {
                Err(format!("no such ban: {key}"))
            }
        }
        BanCmd::List { db } => {
            let store = open_store(&db)?;
            for (cidr, reason, until) in store.ban_rows().map_err(|e| format!("ban list: {e}"))? {
                let until = until.map_or("permanent".into(), |u| u.to_string());
                println!("{cidr}\t{}\t{until}", reason.unwrap_or_default());
            }
            Ok(())
        }
        BanCmd::Export { db } => {
            // The firewall unit runs this before scrip has ever started, when
            // there is no database yet. An empty ruleset is the right answer
            // there, so this one verb treats a missing file as "no bans"
            // rather than an error; every other verb still refuses it, which
            // is what catches a typo'd path.
            if !store_path(&db)?.exists() {
                return Ok(());
            }
            let store = open_store(&db)?;
            let now = scrip::intake::now_epoch();
            for (cidr, _, until) in store.ban_rows().map_err(|e| format!("ban export: {e}"))? {
                if until.is_some_and(|u| u <= now) {
                    continue; // expired
                }
                let Ok(net) = cidr.parse::<ipnet::IpNet>() else {
                    continue; // garbage row: skip rather than emit an nft line that fails the whole import
                };
                let set = match net {
                    ipnet::IpNet::V6(_) => "scrip_bans6",
                    ipnet::IpNet::V4(_) => "scrip_bans4",
                };
                match until {
                    // Hand the expiry to the kernel. The export only ever
                    // adds elements and nothing ever removes them, so an
                    // untimed element makes a 30-minute auto-ban permanent:
                    // the row expires in SQLite while nftables keeps dropping
                    // the source until someone reloads the ruleset by hand.
                    // Both ban sets carry `flags interval,timeout` for this.
                    //
                    // Clamped, because `nft -f` is atomic: one element over
                    // nft's ceiling fails the whole file and leaves the set
                    // empty, taking every valid ban with it. `ban add --for
                    // 3650d` reaches that ceiling, and so does a boot before
                    // the clock is synced, with `now` years behind `until`.
                    // A clamped element expires early in the kernel only; the
                    // in-process list still holds the real duration, and the
                    // next export refreshes it.
                    Some(u) => println!(
                        "add element inet scrip {set} {{ {cidr} timeout {}s }}",
                        (u - now).clamp(1, NFT_MAX_TIMEOUT_SECS)
                    ),
                    None => println!("add element inet scrip {set} {{ {cidr} }}"),
                }
            }
            Ok(())
        }
    }
}

fn rm_cmd(args: RmArgs) -> Result<(), String> {
    let store = open_store(&args.db)?;
    // A takedown usually arrives as a URL. Under encryption at rest the
    // URL segment is the token and the row is keyed by its hash, so when a
    // token-length argument matches no row directly, try its id. The
    // 64-hex id from a log line keeps working as a plain argument.
    let mut gone = store
        .delete_paste(&args.slug)
        .map_err(|e| format!("rm: {e}"))?;
    if !gone && args.slug.len() == scrip::crypto::TOKEN_LEN {
        gone = store
            .delete_paste(&scrip::crypto::token_id(&args.slug))
            .map_err(|e| format!("rm: {e}"))?;
    }
    if gone {
        // Takedown: push the secure_delete-zeroed pages out of the WAL and
        // freelist so the removed bytes leave disk.
        store.scrub().map_err(|e| format!("rm scrub: {e}"))?;
        println!("removed {}", args.slug);
        Ok(())
    } else {
        Err(format!("no such paste: {}", args.slug))
    }
}

fn gc_cmd(args: DbArgs) -> Result<(), String> {
    let store = open_store(&args)?;
    let now = scrip::intake::now_epoch();
    let n = store.delete_expired(now).map_err(|e| format!("gc: {e}"))?;
    let b = store
        .delete_expired_bans(now)
        .map_err(|e| format!("gc: {e}"))?;
    if n > 0 || b > 0 {
        store
            .incremental_vacuum()
            .map_err(|e| format!("gc vacuum: {e}"))?;
    }
    // Swept rows are zeroed in the main file but their old bodies stay in
    // the WAL until it is checkpointed. Best effort: a running daemon may
    // hold it, and its own reaper will get there.
    if !store
        .checkpoint_wal()
        .map_err(|e| format!("gc checkpoint: {e}"))?
    {
        eprintln!("note: wal checkpoint was pinned by another reader; deleted bodies may remain in scrip.db-wal until it clears");
    }
    if b > 0 {
        println!("removed {n} expired pastes, {b} expired bans");
    } else {
        println!("removed {n} expired pastes");
    }
    Ok(())
}

fn init_tracing(stderr: bool) {
    if stderr {
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(std::io::stderr)
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .init();
    }
}

fn main() {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Run(_) => init_tracing(false),
        _ => init_tracing(true),
    }
    let result = match cli.cmd {
        Cmd::Run(a) => {
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            rt.block_on(run(a))
        }
        Cmd::Ban(a) => ban_cmd(a.cmd),
        Cmd::Rm(a) => rm_cmd(a),
        Cmd::Gc(a) => gc_cmd(a),
    };
    if let Err(e) = result {
        eprintln!("scrip: {e}");
        std::process::exit(1);
    }
}

async fn run(args: RunArgs) -> Result<(), String> {
    // Flags win over file values over defaults.
    let mut config = Config::load(args.config.as_deref())?;
    if let Some(db) = args.db {
        config.db_path = db;
    }
    if let Some(b) = args.base_url {
        config.base_url = b;
    }
    if !args.listen_tcp.is_empty() {
        config.listen_tcp = args.listen_tcp;
    }
    config.validate()?;

    if config.listen_http.is_empty() {
        tracing::warn!("HTTP surface disabled");
    }
    for addr in &config.listen_http {
        if !addr.ip().is_loopback() {
            tracing::warn!(
                "X-Forwarded-For is trusted from loopback only; fronting proxy required"
            );
        }
    }

    let store = Store::open(&config.db_path)
        .map_err(|e| format!("open db {}: {e}", config.db_path.display()))?;

    let max_conns = config.max_conns;
    let ctx = Arc::new(Ctx::new(config, store));

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut tasks = Vec::new();

    // One synchronous ban load before binding listeners so bans apply from
    // the first accepted connection, not just after the first reload tick.
    {
        let st = ctx.store.clone();
        match tokio::task::spawn_blocking(move || st.bans()).await {
            Ok(Ok(b)) => ctx.bans.replace(b),
            Ok(Err(e)) => tracing::error!("initial ban load: {e}"),
            Err(e) => tracing::error!("initial ban load task panicked: {e}"),
        }
    }

    for addr in ctx.config.listen_tcp.clone() {
        let std_listener = intake::bind_tcp(addr).map_err(|e| format!("bind {addr}: {e}"))?;
        let listener = tokio::net::TcpListener::from_std(std_listener)
            .map_err(|e| format!("register listener {addr}: {e}"))?;
        tracing::info!("listening on {}", listener.local_addr().unwrap());
        tasks.push(tokio::spawn(intake::accept_loop(
            listener,
            ctx.clone(),
            shutdown_rx.clone(),
        )));
    }

    for addr in ctx.config.listen_http.clone() {
        let std_listener = intake::bind_tcp(addr).map_err(|e| format!("bind http {addr}: {e}"))?;
        let listener = tokio::net::TcpListener::from_std(std_listener)
            .map_err(|e| format!("register http listener {addr}: {e}"))?;
        tracing::info!("http listening on {}", listener.local_addr().unwrap());
        tasks.push(scrip::http::serve(
            listener,
            ctx.clone(),
            shutdown_rx.clone(),
        ));
    }

    // Ban reload: bans apply without a restart.
    {
        let ctx = ctx.clone();
        let mut rx = shutdown_rx.clone();
        let ban_reload_secs = ctx.config.ban_reload_secs;
        tasks.push(tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(ban_reload_secs));
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    _ = iv.tick() => {
                        let st = ctx.store.clone();
                        match tokio::task::spawn_blocking(move || st.bans()).await {
                            Ok(Ok(b)) => ctx.bans.replace(b),
                            Ok(Err(e)) => tracing::error!("ban reload: {e}"),
                            Err(e) => tracing::error!("ban reload task panicked: {e}"),
                        }
                    }
                }
            }
        }));
    }

    // Rate-limiter bucket + auto-ban violation-tracker eviction.
    {
        let ctx = ctx.clone();
        let mut rx = shutdown_rx.clone();
        // Generous relative to the window so a source mid-way through
        // accumulating refusals is never evicted out from under itself.
        let violation_idle = Duration::from_secs((2 * ctx.config.autoban_window_secs).max(300));
        tasks.push(tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    _ = iv.tick() => {
                        let now = std::time::Instant::now();
                        ctx.limiter.evict_idle(now, Duration::from_secs(300));
                        ctx.violations.evict_idle(now, violation_idle);
                    }
                }
            }
        }));
    }

    // Reaper: retention is enforced here; the read path filters on expires_at
    // so the window between expiry and this tick serves nothing.
    {
        let ctx = ctx.clone();
        let mut rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(ctx.config.gc_interval_secs));
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    _ = iv.tick() => {
                        let st = ctx.store.clone();
                        let forget_days = ctx.config.autoban_forget_days;
                        let r = tokio::task::spawn_blocking(move || -> rusqlite::Result<(usize, usize, usize, bool)> {
                            let now = scrip::intake::now_epoch();
                            let n = st.delete_expired(now)?;
                            let b = st.delete_expired_bans(now)?;
                            let o = if forget_days > 0 {
                                st.forget_stale_offenses(now - forget_days as i64 * 86_400)?
                            } else {
                                0
                            };
                            if n > 0 || b > 0 {
                                st.incremental_vacuum()?;
                            }
                            // Unconditional, not gated on this tick having
                            // deleted anything: burn-after-read and token
                            // deletes happen on the request path between
                            // ticks, and their bodies sit in the WAL until a
                            // checkpoint restarts it. Best effort, so a
                            // reader pinning the WAL defers to the next tick
                            // instead of failing the sweep.
                            let checkpointed = st.checkpoint_wal()?;
                            Ok((n, b, o, checkpointed))
                        })
                        .await;
                        match r {
                            Ok(Ok((0, 0, 0, true))) => {}
                            Ok(Ok((0, 0, 0, false))) => {
                                tracing::debug!("reaper: wal checkpoint pinned by a reader, retrying next tick");
                            }
                            Ok(Ok((n, b, o, _))) => {
                                let mut msg = format!("reaper removed {n} expired pastes");
                                if b > 0 {
                                    msg.push_str(&format!(" and {b} expired bans"));
                                }
                                if o > 0 {
                                    msg.push_str(&format!(", forgot {o} stale offense records"));
                                }
                                tracing::info!("{msg}");
                            }
                            Ok(Err(e)) => tracing::error!("reaper: {e}"),
                            Err(e) => tracing::error!("reaper: task panicked: {e}"),
                        }
                    }
                }
            }
        }));
    }

    wait_for_signal().await;
    tracing::info!("shutting down");
    let _ = shutdown_tx.send(true);

    // Drain: every permit back means every TCP connection closed and every
    // in-flight HTTP request finished.
    let drain = ctx.conn_sem.clone().acquire_many_owned(max_conns as u32);
    if tokio::time::timeout(Duration::from_secs(10), drain)
        .await
        .is_err()
    {
        tracing::warn!("drain deadline hit, exiting with connections open");
    }
    for t in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(1), t).await;
    }
    // The reaper has stopped. Checkpoint once more to remove WAL frames from
    // request-path deletes before shutdown; otherwise a backup taken during
    // downtime could still contain those bodies.
    {
        let st = ctx.store.clone();
        match tokio::task::spawn_blocking(move || st.checkpoint_wal()).await {
            Ok(Ok(true)) | Err(_) => {}
            Ok(Ok(false)) => tracing::warn!("shutdown: wal checkpoint pinned, wal left in place"),
            Ok(Err(e)) => tracing::warn!("shutdown: wal checkpoint failed: {e}"),
        }
    }
    Ok(())
}

async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = term.recv() => {},
        _ = tokio::signal::ctrl_c() => {},
    }
}
