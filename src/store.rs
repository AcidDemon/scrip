use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};

type BanRow = (String, Option<String>, Option<i64>);

/// How long a statement waits on a locked database before giving up. Applies
/// to every query on the shared connection.
const BUSY_TIMEOUT_MS: i32 = 5000;

/// Per-row overhead charged on top of body bytes (index entries, page slack)
/// so quota accounting reflects disk use, not just blob size. Without it,
/// tiny pastes amplify real disk usage far past what they report.
pub const ROW_OVERHEAD: u64 = 128;

/// The exact aggregate the `Store::total` cache mirrors, straight from the
/// table. Used to seed the cache at open and to re-seed it wherever another
/// process (`scrip rm`, `scrip ban add --purge`, `scrip gc`) may have deleted
/// rows this process never saw.
fn real_total(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COALESCE(SUM(size), 0) + COUNT(*) * ?1 FROM paste",
        params![ROW_OVERHEAD as i64],
        |r| r.get(0),
    )
}

fn has_column(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for name in names {
        if name? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS paste (
  slug       TEXT    PRIMARY KEY,
  body       BLOB    NOT NULL,
  size       INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  source_ip  TEXT,
  source_key TEXT,
  burn       INTEGER NOT NULL DEFAULT 0,
  delete_token_hash BLOB
) STRICT;
CREATE INDEX IF NOT EXISTS paste_expires ON paste(expires_at);
CREATE INDEX IF NOT EXISTS paste_size ON paste(size);

CREATE TABLE IF NOT EXISTS ban (
  cidr   TEXT PRIMARY KEY,
  reason TEXT,
  until  INTEGER
) STRICT;

CREATE TABLE IF NOT EXISTS offense (
  source_key TEXT PRIMARY KEY,
  strikes    INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL
) STRICT;
";

/// Outcome of `Store::make_room`: either the paste fits now (with what the
/// eviction cost), or nothing old enough to evict remained and the caller
/// must refuse the write.
#[derive(Debug, PartialEq, Eq)]
pub enum RoomOutcome {
    Fits { evicted: usize, bytes: u64 },
    Full,
}

/// One connection behind a mutex, callers use spawn_blocking. WAL has a
/// single writer anyway; a pool if read volume ever demands it.
#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
    /// Running SUM(size) + COUNT(*) * ROW_OVERHEAD over paste, seeded from
    /// the real SUM at open and kept in step by every insert/delete path, so
    /// the per-paste quota check is an atomic load instead of a table scan.
    // The counter is updated separately from the commit. open, make_room,
    // and the reaper re-seed it; an atomic update would need a SQLite counter.
    total: Arc<AtomicI64>,
}

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Store> {
        let mut conn = Connection::open(path)?;
        // auto_vacuum must be set before journal_mode=WAL writes the DB
        // header, or it silently no-ops.
        conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // Fsync each paste before returning its URL. NORMAL waits until the
        // next checkpoint, so a power cut could lose an acknowledged upload.
        // This costs one fsync per paste, with a default limit of 6/min/source.
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "busy_timeout", BUSY_TIMEOUT_MS)?;
        // Zero deleted row images. The WAL also needs a checkpoint to remove
        // frames that contain the old body.
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Store::migrate_source_key(&mut conn)?;
        Store::migrate_mapped_bans(&mut conn)?;
        Store::migrate_paste_options(&mut conn)?;
        conn.execute_batch("CREATE INDEX IF NOT EXISTS paste_source_key ON paste(source_key);")?;
        let total = real_total(&conn)?;
        Ok(Store {
            conn: Arc::new(Mutex::new(conn)),
            total: Arc::new(AtomicI64::new(total)),
        })
    }

    /// Adds `source_key` if an old database is missing it, then backfills
    /// every row where it's still NULL but `source_ip` is known. The
    /// backfill runs unconditionally on every open (not gated on the column
    /// having just been added) and only ever touches NULL rows, so it's
    /// naturally idempotent: a crash between the ALTER and the last UPDATE
    /// just leaves some rows NULL, and the next open finishes them off
    /// instead of skipping the table forever. Column-add and backfill share
    /// one transaction so a crash mid-way never leaves the column present
    /// with no backfill attempted at all.
    fn migrate_source_key(conn: &mut Connection) -> rusqlite::Result<()> {
        let tx = conn.transaction()?;
        if !has_column(&tx, "paste", "source_key")? {
            tx.execute_batch("ALTER TABLE paste ADD COLUMN source_key TEXT;")?;
        }
        // Batched, so an un-backfilled store with millions of rows does not
        // materialise all of them at once before the listeners are even bound.
        // Paged by rowid rather than by a bare LIMIT: a row whose `source_ip`
        // does not parse keeps its NULL key, so a LIMIT-only query would hand
        // back the same unparseable rows forever and never reach the rest.
        const BACKFILL_BATCH: i64 = 10_000;
        let mut after: i64 = 0;
        loop {
            let mut stmt = tx.prepare(
                "SELECT rowid, slug, source_ip FROM paste
                 WHERE source_key IS NULL AND source_ip IS NOT NULL AND rowid > ?1
                 ORDER BY rowid LIMIT ?2",
            )?;
            let rows: Vec<(i64, String, String)> = stmt
                .query_map(params![after, BACKFILL_BATCH], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?
                .collect::<rusqlite::Result<_>>()?;
            drop(stmt);
            let Some((last, _, _)) = rows.last() else {
                break;
            };
            after = *last;
            for (_, slug, ip) in rows {
                if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                    let key = crate::policy::source_key(addr).to_string();
                    tx.execute(
                        "UPDATE paste SET source_key = ?1 WHERE slug = ?2",
                        params![key, slug],
                    )?;
                }
            }
        }
        tx.commit()
    }

    /// Rewrites ban rows stranded by IP canonicalization. Ban checks now
    /// compare against `to_canonical()` addresses, so a row written in
    /// IPv4-mapped form (a CIDR inside ::ffff:0:0/96) can never match again:
    /// cross-family `contains` is always false. Each such row becomes the
    /// equivalent IPv4 CIDR (prefix len minus 96), merged extend-style so an
    /// existing v4 twin is never shortened. The old truncation bug also
    /// keyed every mapped client as ::/64 and auto-banned that; those rows
    /// go, while an operator-written ::/64 stays. Idempotent: a rewritten
    /// row no longer parses as a mapped v6 net, and the ::/64 delete matches
    /// nothing the second time.
    fn migrate_mapped_bans(conn: &mut Connection) -> rusqlite::Result<()> {
        let tx = conn.transaction()?;
        let rows: Vec<BanRow> = {
            let mut stmt = tx.prepare("SELECT cidr, reason, until FROM ban")?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for (cidr, reason, until) in rows {
            let Ok(ipnet::IpNet::V6(net)) = cidr.parse::<ipnet::IpNet>() else {
                continue;
            };
            if net.prefix_len() < 96 {
                continue; // wider than the mapped range: genuinely v6
            }
            let Some(v4) = net.addr().to_ipv4_mapped() else {
                continue;
            };
            let v4net = ipnet::Ipv4Net::new(v4, net.prefix_len() - 96)
                .expect("prefix - 96 <= 32")
                .trunc();
            upsert_ban_extending(&tx, &v4net.to_string(), reason.as_deref(), until)?;
            tx.execute("DELETE FROM ban WHERE cidr = ?1", params![cidr])?;
        }
        tx.execute(
            "DELETE FROM ban WHERE cidr = '::/64' AND reason LIKE 'auto:%'",
            [],
        )?;
        tx.commit()
    }

    /// Adds the per-paste option columns (`burn`, `delete_token_hash`) to a
    /// database created before they existed. Guarded ALTERs in one
    /// transaction, same rerunnable shape as `migrate_source_key`; old rows
    /// keep burn = 0 and a NULL token hash, which no presented token can
    /// ever match.
    fn migrate_paste_options(conn: &mut Connection) -> rusqlite::Result<()> {
        let tx = conn.transaction()?;
        if !has_column(&tx, "paste", "burn")? {
            tx.execute_batch("ALTER TABLE paste ADD COLUMN burn INTEGER NOT NULL DEFAULT 0;")?;
        }
        if !has_column(&tx, "paste", "delete_token_hash")? {
            tx.execute_batch("ALTER TABLE paste ADD COLUMN delete_token_hash BLOB;")?;
        }
        tx.commit()
    }

    /// Ok(false) = slug already exists (PRIMARY KEY conflict). Caller decides
    /// whether to regenerate; this function never loops.
    pub fn insert_paste(
        &self,
        slug: &str,
        body: &[u8],
        source_ip: &str,
        created_at: i64,
        expires_at: i64,
    ) -> rusqlite::Result<bool> {
        self.insert_paste_opts(slug, body, source_ip, created_at, expires_at, false, None)
    }

    /// The full insert behind `insert_paste`: `burn` marks the row to be
    /// destroyed on its first raw read, `delete_token_hash` (SHA-256 of the
    /// token handed to the uploader) authorizes HTTP DELETE.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_paste_opts(
        &self,
        slug: &str,
        body: &[u8],
        source_ip: &str,
        created_at: i64,
        expires_at: i64,
        burn: bool,
        delete_token_hash: Option<&[u8]>,
    ) -> rusqlite::Result<bool> {
        let key = source_ip
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| crate::policy::source_key(ip).to_string());
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let r = conn.execute(
            "INSERT INTO paste (slug, body, size, created_at, expires_at, source_ip, source_key,
                                burn, delete_token_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                slug,
                body,
                body.len() as i64,
                created_at,
                expires_at,
                source_ip,
                key,
                burn as i64,
                delete_token_hash
            ],
        );
        match r {
            Ok(_) => {
                self.total
                    .fetch_add(body.len() as i64 + ROW_OVERHEAD as i64, Ordering::Relaxed);
                Ok(true)
            }
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Burn rows are excluded on purpose: `claim_burn` is their only way
    /// out, so no plain read path can leak a burn body and leave the row
    /// alive for a second reader.
    pub fn get_paste(&self, slug: &str) -> rusqlite::Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT body FROM paste WHERE slug = ?1 AND burn = 0 AND expires_at > unixepoch()",
            params![slug],
            |r| r.get(0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })
    }

    /// Atomic take for burn-after-read: one DELETE ... RETURNING, so however
    /// many readers race, exactly one gets the body and the rest see None.
    /// secure_delete then zeroes the row image on disk. Returns None for
    /// non-burn rows too; callers fall back to `get_paste`.
    pub fn claim_burn(&self, slug: &str) -> rusqlite::Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let row: Option<(Vec<u8>, i64)> = conn
            .query_row(
                "DELETE FROM paste WHERE slug = ?1 AND burn = 1 AND expires_at > unixepoch()
                 RETURNING body, size",
                params![slug],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(e),
            })?;
        let Some((body, size)) = row else {
            return Ok(None);
        };
        self.total
            .fetch_sub(size + ROW_OVERHEAD as i64, Ordering::Relaxed);
        drop(conn);
        self.checkpoint_after_destroy("burn-after-read");
        Ok(Some(body))
    }

    /// Attempts a WAL checkpoint after a burn read or token delete.
    /// `secure_delete` zeroes the row, but old body frames remain in the WAL
    /// until a checkpoint. Try immediately instead of waiting up to
    /// `gc_interval_secs` for the reaper. A reader pinning the WAL defers
    /// cleanup to a later checkpoint; the committed delete still succeeds.
    fn checkpoint_after_destroy(&self, what: &str) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // A TRUNCATE checkpoint needs all readers to release their snapshots.
        // Do not hold the mutex for BUSY_TIMEOUT_MS waiting on another process
        // (for example, a backup). Return immediately and let the reaper retry.
        let lowered = conn.pragma_update(None, "busy_timeout", 0).is_ok();
        let r = checkpoint_truncate(&conn);
        if lowered {
            let _ = conn.pragma_update(None, "busy_timeout", BUSY_TIMEOUT_MS);
        }
        match r {
            Ok(true) => {}
            Ok(false) => tracing::debug!("{what}: wal checkpoint pinned by a reader"),
            Err(e) => tracing::warn!("{what}: wal checkpoint failed: {e}"),
        }
    }

    /// Some(burn) for a live paste, None otherwise. The viewer uses this to
    /// pick the burn warning page over the auto-fetching shell (which would
    /// consume the paste just by being opened).
    pub fn burn_status(&self, slug: &str) -> rusqlite::Result<Option<bool>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT burn FROM paste WHERE slug = ?1 AND expires_at > unixepoch()",
            params![slug],
            |r| r.get::<_, i64>(0).map(|b| b != 0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })
    }

    /// Token-authorized delete: one statement, so a wrong token and a
    /// missing row are the same non-event. Old rows carry a NULL hash and
    /// can never match.
    pub fn delete_by_token(&self, slug: &str, token_hash: &[u8]) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let size: Option<i64> = conn
            .query_row(
                "DELETE FROM paste WHERE slug = ?1 AND delete_token_hash = ?2 RETURNING size",
                params![slug, token_hash],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(e),
            })?;
        match size {
            Some(size) => {
                self.total
                    .fetch_sub(size + ROW_OVERHEAD as i64, Ordering::Relaxed);
                drop(conn);
                self.checkpoint_after_destroy("token delete");
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Existence check without fetching the blob.
    pub fn exists(&self, slug: &str) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT 1 FROM paste WHERE slug = ?1 AND expires_at > unixepoch()",
            params![slug],
            |_| Ok(()),
        )
        .map(|()| true)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(false),
            e => Err(e),
        })
    }

    /// Sum of body bytes plus ROW_OVERHEAD per row, from the cached running
    /// total. Clamped at 0: a transiently negative value (racing adjustments)
    /// must not wrap into an enormous u64.
    pub fn total_size(&self) -> u64 {
        self.total.load(Ordering::Relaxed).max(0) as u64
    }

    /// Upserts a strike for `source_key`, returning the new strike count.
    pub fn record_offense(&self, source_key: &str, now: i64) -> rusqlite::Result<u32> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "INSERT INTO offense (source_key, strikes, last_seen) VALUES (?1, 1, ?2)
             ON CONFLICT(source_key) DO UPDATE SET strikes = strikes + 1, last_seen = ?2
             RETURNING strikes",
            params![source_key, now],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| v as u32)
    }

    pub fn forget_stale_offenses(&self, cutoff: i64) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute("DELETE FROM offense WHERE last_seen < ?1", params![cutoff])
    }

    pub fn forget_offense(&self, source_key: &str) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        Ok(conn.execute(
            "DELETE FROM offense WHERE source_key = ?1",
            params![source_key],
        )? > 0)
    }

    pub fn offense_strikes(&self) -> rusqlite::Result<std::collections::HashMap<String, u32>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare("SELECT source_key, strikes FROM offense")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u32)))?;
        rows.collect()
    }

    /// Live pastes only: the budget frees up as pastes expire or are deleted.
    pub fn count_by_source_key(&self, key: &str) -> rusqlite::Result<u32> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT COUNT(*) FROM paste WHERE source_key = ?1 AND expires_at > unixepoch()",
            params![key],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| v as u32)
    }

    /// The /48 aggregate of `count_by_source_key`: live pastes across every
    /// /64 key inside the /48. Keys are stored as /64 display strings, and
    /// every one inside the /48 spells its three leading groups out in full
    /// ("2001:db8:1:2::") except the /48's own network address, whose zero
    /// run swallows the fourth group ("2001:db8:1::"), so match the prefix
    /// plus that one exact form. A half-open range uses the paste_source_key
    /// index; `LIKE ?1 || '%'` requires a full scan under the global mutex.
    pub fn count_by_source_key48(&self, key48: std::net::Ipv6Addr) -> rusqlite::Result<u32> {
        let s = key48.segments();
        let prefix = format!("{:x}:{:x}:{:x}:", s[0], s[1], s[2]);
        // The successor string of the prefix: exactly the keys starting with
        // the prefix sort inside [prefix, upper). Keys are ASCII hex plus
        // ':' (0x3a), so bumping the final ':' to ';' never overflows.
        let upper = {
            let mut b = prefix.clone().into_bytes();
            *b.last_mut().expect("prefix is never empty") += 1;
            String::from_utf8(b).expect("ascii stays ascii")
        };
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            COUNT48_SQL,
            params![prefix, upper, key48.to_string()],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| v as u32)
    }

    /// Active auto-ban rows on sibling /64s inside the /48, excluding `own`
    /// (the /64 currently being banned). Feeds the decision to escalate an
    /// auto-ban to the covering /48; same display-form matching as
    /// `count_by_source_key48`. Auto-bans are always timed, so permanent
    /// operator rows never count.
    pub fn count_sibling_autobans48(
        &self,
        key48: std::net::Ipv6Addr,
        own: &str,
        now: i64,
    ) -> rusqlite::Result<u32> {
        let s = key48.segments();
        let prefix = format!("{:x}:{:x}:{:x}:", s[0], s[1], s[2]);
        let exact = format!("{key48}/64");
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT COUNT(*) FROM ban
             WHERE (cidr LIKE ?1 || '%' OR cidr = ?2) AND cidr LIKE '%/64'
               AND cidr <> ?3 AND reason LIKE 'auto%'
               AND until IS NOT NULL AND until > ?4",
            params![prefix, exact, own, now],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| v as u32)
    }

    pub fn add_ban(
        &self,
        cidr: &str,
        reason: Option<&str>,
        until: Option<i64>,
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT OR REPLACE INTO ban (cidr, reason, until) VALUES (?1, ?2, ?3)",
            params![cidr, reason, until],
        )?;
        Ok(())
    }

    /// Extension-only upsert for the auto-ban path: a permanent ban (until
    /// NULL) stays permanent and a timed ban only ever grows, so a 30-minute
    /// auto-ban can never clobber an operator's longer one down to something
    /// the reaper deletes. An existing reason is kept. The CLI's `add_ban`
    /// deliberately keeps overwrite semantics: the operator stays
    /// authoritative.
    pub fn extend_ban(
        &self,
        cidr: &str,
        reason: Option<&str>,
        until: Option<i64>,
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        upsert_ban_extending(&conn, cidr, reason, until)
    }

    pub fn bans(&self) -> rusqlite::Result<Vec<(ipnet::IpNet, Option<i64>)>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare("SELECT cidr, until FROM ban")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (cidr, until) = row?;
            match cidr.parse::<ipnet::IpNet>() {
                Ok(net) => out.push((net, until)),
                Err(_) => tracing::warn!("ignoring unparseable ban row: {cidr}"),
            }
        }
        Ok(out)
    }

    /// Removes expired rows in bounded batches, releasing the connection
    /// mutex between batches so a huge backlog never stalls readers for the
    /// whole sweep. Returns the total rows removed.
    pub fn delete_expired(&self, now: i64) -> rusqlite::Result<usize> {
        const BATCH: usize = 10_000;
        let mut removed = 0;
        loop {
            let n = {
                let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
                let mut stmt = conn.prepare(
                    "DELETE FROM paste WHERE rowid IN (
                       SELECT rowid FROM paste WHERE expires_at <= ?1 LIMIT ?2)
                     RETURNING size",
                )?;
                // query_map steps to completion, which is what actually
                // applies every delete in the batch.
                let sizes: Vec<i64> = stmt
                    .query_map(params![now, BATCH as i64], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                let bytes: i64 = sizes.iter().map(|s| s + ROW_OVERHEAD as i64).sum();
                self.total.fetch_sub(bytes, Ordering::Relaxed);
                if sizes.len() < BATCH {
                    // Last batch of the sweep: end on the exact aggregate, so
                    // drift from CLI-process deletes this cache never saw is
                    // washed out every reaper tick, not only at open.
                    let real = real_total(&conn)?;
                    self.total.store(real, Ordering::Relaxed);
                }
                sizes.len()
            };
            removed += n;
            if n < BATCH {
                return Ok(removed);
            }
        }
    }

    pub fn delete_expired_bans(&self, now: i64) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "DELETE FROM ban WHERE until IS NOT NULL AND until <= ?1",
            params![now],
        )
    }

    pub fn incremental_vacuum(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // Bounded stall (~1000 pages) instead of draining the whole freelist
        // under the global mutex; the remainder drains over subsequent ticks.
        conn.execute_batch("PRAGMA incremental_vacuum(1000);")
    }

    pub fn delete_paste(&self, slug: &str) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // RETURNING gives the exact bytes to debit; slug is the PK so at most
        // one row comes back and a single step applies the whole delete.
        let size: Option<i64> = conn
            .query_row(
                "DELETE FROM paste WHERE slug = ?1 RETURNING size",
                params![slug],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(e),
            })?;
        match size {
            Some(size) => {
                self.total
                    .fetch_sub(size + ROW_OVERHEAD as i64, Ordering::Relaxed);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn remove_ban(&self, cidr: &str) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        Ok(conn.execute("DELETE FROM ban WHERE cidr = ?1", params![cidr])? > 0)
    }

    pub fn ban_rows(&self) -> rusqlite::Result<Vec<BanRow>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare("SELECT cidr, reason, until FROM ban ORDER BY cidr")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect()
    }

    /// Ban plus purge in one transaction: either the ban lands and every
    /// matching paste is gone, or nothing changed.
    pub fn add_ban_with_purge(
        &self,
        cidr: &ipnet::IpNet,
        reason: Option<&str>,
        until: Option<i64>,
    ) -> rusqlite::Result<usize> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT OR REPLACE INTO ban (cidr, reason, until) VALUES (?1, ?2, ?3)",
            params![cidr.trunc().to_string(), reason, until],
        )?;
        let victims: Vec<(String, i64)> = {
            let mut stmt =
                tx.prepare("SELECT slug, source_ip, size FROM paste WHERE source_ip IS NOT NULL")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?;
            let mut v = Vec::new();
            for row in rows {
                let (slug, ip, size) = row?;
                if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                    if cidr.contains(&addr) {
                        v.push((slug, size));
                    }
                }
            }
            v
        };
        let mut purged = 0;
        let mut bytes = 0i64;
        for (slug, size) in &victims {
            purged += tx.execute("DELETE FROM paste WHERE slug = ?1", params![slug])?;
            bytes += size + ROW_OVERHEAD as i64;
        }
        tx.commit()?;
        // Debit only after the commit: a rolled-back purge changed nothing.
        self.total.fetch_sub(bytes, Ordering::Relaxed);
        Ok(purged)
    }

    /// Evicts until `need` more bytes fit under `quota`, in bounded batches
    /// with the mutex released between them. Frees only as much as the deficit
    /// demands, never a whole batch for its own sake.
    ///
    /// Evicts expired rows first, regardless of age, then live pastes older
    /// than half their retention. Newer live pastes are protected, so quota
    /// pressure cannot delete them. Returns `Full` if eligible evictions
    /// cannot free enough space.
    // The age floor is fixed at retention_days/2. Make it configurable if
    // operators need a different minimum age for eviction.
    pub fn make_room(
        &self,
        need: u64,
        quota: u64,
        retention_days: u64,
    ) -> rusqlite::Result<RoomOutcome> {
        const BATCH: usize = 50;
        let min_age_secs = (retention_days * 86_400 / 2) as i64;
        let mut evicted = 0;
        let mut freed_total = 0u64;
        {
            // The CLI (`scrip rm`, `scrip ban add --purge`, `scrip gc`)
            // deletes rows from a separate process this cache never sees, so
            // re-seed from the real aggregate before any eviction decision;
            // a phantom deficit must not evict live pastes. Evictions are
            // rare, so the scan is nearly free.
            let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            let real = real_total(&conn)?;
            self.total.store(real, Ordering::Relaxed);
            if real.max(0) as u64 + need <= quota {
                return Ok(RoomOutcome::Fits {
                    evicted: 0,
                    bytes: 0,
                });
            }
        }
        loop {
            let used = self.total_size();
            if used + need <= quota {
                return Ok(RoomOutcome::Fits {
                    evicted,
                    bytes: freed_total,
                });
            }
            let deficit = used + need - quota;
            let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            // Expired rows no longer need age protection. Reclaim them
            // here so uploads do not have to wait for the next reaper tick.
            let mut stmt = conn.prepare(
                "SELECT rowid, size FROM paste
                 WHERE expires_at <= unixepoch() OR created_at <= unixepoch() - ?1
                 ORDER BY (expires_at > unixepoch()), created_at, rowid LIMIT ?2",
            )?;
            let rows: Vec<(i64, i64)> = stmt
                .query_map(params![min_age_secs, BATCH as i64], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?
                .collect::<rusqlite::Result<_>>()?;
            drop(stmt);
            if rows.is_empty() {
                return Ok(RoomOutcome::Full); // nothing old enough left: refuse the write
            }
            let mut freed = 0u64;
            for (rowid, size) in rows {
                conn.execute("DELETE FROM paste WHERE rowid = ?1", params![rowid])?;
                freed += size as u64 + ROW_OVERHEAD;
                evicted += 1;
                if freed >= deficit {
                    break;
                }
            }
            self.total.fetch_sub(freed as i64, Ordering::Relaxed);
            freed_total += freed;
        }
    }

    /// Best-effort WAL checkpoint for the periodic sweep. Deleting a row
    /// zeroes its image in the main file, but in WAL mode the frames still
    /// holding the old body live on in scrip.db-wal until a TRUNCATE
    /// checkpoint restarts it, so every routine delete (expiry, eviction,
    /// burn-after-read, a token delete) leaves a carvable copy behind.
    /// Unlike `scrub`, a blocked checkpoint is not an error here: a reader
    /// pinning the WAL just defers the work to the next sweep, which must
    /// not fail over it. Ok(false) = still pinned, try again next tick.
    pub fn checkpoint_wal(&self) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        checkpoint_truncate(&conn)
    }

    /// Post-takedown flush: checkpoint the WAL into the main file and
    /// truncate it, then drain the freelist. secure_delete zeroed the row
    /// images at delete time. If a reader or writer blocks the checkpoint,
    /// old plaintext frames remain in the WAL. Retry briefly, then return
    /// an error if the checkpoint still cannot complete.
    pub fn scrub(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        for attempt in 0..3 {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            if checkpoint_truncate(&conn)? {
                return conn.execute_batch("PRAGMA incremental_vacuum;");
            }
        }
        Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some(SCRUB_BLOCKED_MSG.into()),
        ))
    }
}

/// Shared with the query-plan test, which checks that the index is used.
const COUNT48_SQL: &str = "SELECT COUNT(*) FROM paste
 WHERE ((source_key >= ?1 AND source_key < ?2) OR source_key = ?3)
   AND expires_at > unixepoch()";

/// Extension-only ban upsert (see `Store::extend_ban` for the semantics),
/// shared with the open-time migration that rewrites mapped rows.
fn upsert_ban_extending(
    conn: &Connection,
    cidr: &str,
    reason: Option<&str>,
    until: Option<i64>,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO ban (cidr, reason, until) VALUES (?1, ?2, ?3)
         ON CONFLICT(cidr) DO UPDATE SET
           until = CASE WHEN ban.until IS NULL OR excluded.until IS NULL
                        THEN NULL ELSE MAX(ban.until, excluded.until) END,
           reason = COALESCE(ban.reason, excluded.reason)",
        params![cidr, reason, until],
    )?;
    Ok(())
}

/// What a takedown must report when the WAL cannot be flushed: the row is
/// gone, but its plaintext frames are still on disk in scrip.db-wal.
const SCRUB_BLOCKED_MSG: &str =
    "checkpoint blocked: content may remain in the WAL; retry, or stop the service and re-run";

/// One `PRAGMA wal_checkpoint(TRUNCATE)` attempt. The pragma reports being
/// blocked in-band: rc is OK but the row's first (busy) column is 1 when a
/// concurrent reader or writer stopped the checkpoint from completing, so
/// that column must be read, not discarded. Ok(true) = WAL fully
/// checkpointed and truncated.
fn checkpoint_truncate(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
        r.get::<_, i64>(0).map(|busy| busy == 0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_fails_loudly_when_a_reader_pins_the_wal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let s = Store::open(&path).unwrap();
        s.insert_paste("pinnedok", b"x", "::1", 1, i64::MAX)
            .unwrap();
        // Drop the 5s busy handler so the blocked checkpoint reports busy
        // immediately instead of stalling this test for 3 x 5s.
        s.conn
            .lock()
            .unwrap()
            .pragma_update(None, "busy_timeout", 0)
            .unwrap();
        // A reader holding an open snapshot (any other process, in
        // production) blocks the TRUNCATE checkpoint from restarting the WAL.
        let reader = Connection::open(&path).unwrap();
        let tx = reader.unchecked_transaction().unwrap();
        let _: i64 = tx
            .query_row("SELECT COUNT(*) FROM paste", [], |r| r.get(0))
            .unwrap();
        let err = s.scrub().expect_err("a pinned WAL must fail the scrub");
        assert!(
            err.to_string().contains("content may remain in the WAL"),
            "unhelpful scrub error: {err}"
        );
        drop(tx);
        drop(reader);
        // busy=0 path: an idle db checkpoints and scrub succeeds
        s.scrub()
            .expect("scrub must succeed once the reader is gone");
    }

    #[test]
    fn count48_query_plan_uses_the_source_key_index() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("t.db")).unwrap();
        let conn = s.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {COUNT48_SQL}"))
            .unwrap();
        let plan = stmt
            .query_map(params!["2001:db8:1:", "2001:db8:1;", "2001:db8:1::"], |r| {
                r.get::<_, String>(3)
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
            .join("\n");
        assert!(
            plan.contains("paste_source_key"),
            "the /48 count must be served by the index: {plan}"
        );
        assert!(
            !plan.contains("SCAN paste"),
            "the /48 count must not full-scan the table: {plan}"
        );
    }
}
