use scrip::policy::BanList;
use scrip::store::{RoomOutcome, Store};

mod support;
use support::far;

fn temp_store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let s = Store::open(&dir.path().join("t.db")).unwrap();
    (dir, s)
}

#[test]
fn insert_and_fetch_roundtrip() {
    let (_d, s) = temp_store();
    assert!(s
        .insert_paste("abcd1234", b"hello\x00world", "127.0.0.1", 100, far())
        .unwrap());
    assert_eq!(s.get_paste("abcd1234").unwrap().unwrap(), b"hello\x00world");
    assert_eq!(s.get_paste("nosuch00").unwrap(), None);
}

#[test]
fn duplicate_slug_reports_conflict_not_error() {
    let (_d, s) = temp_store();
    assert!(s
        .insert_paste("aaaaaaaa", b"one", "127.0.0.1", 1, far())
        .unwrap());
    assert!(!s
        .insert_paste("aaaaaaaa", b"two", "127.0.0.1", 1, far())
        .unwrap());
    // first body survives
    assert_eq!(s.get_paste("aaaaaaaa").unwrap().unwrap(), b"one");
}

#[test]
fn concurrent_inserts_of_same_slug_yield_exactly_one_winner() {
    let (_d, s) = temp_store();
    let wins: usize = std::thread::scope(|scope| {
        (0..16)
            .map(|_| {
                let s = s.clone();
                scope.spawn(move || {
                    s.insert_paste("race0000", b"x", "::1", 1, far()).unwrap() as usize
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .sum()
    });
    assert_eq!(wins, 1);
}

#[test]
fn total_size_sums_bodies_and_is_zero_when_empty() {
    let (_d, s) = temp_store();
    assert_eq!(s.total_size(), 0);
    s.insert_paste("bbbbbbbb", &[0u8; 100], "::1", 1, far())
        .unwrap();
    s.insert_paste("cccccccc", &[0u8; 50], "::1", 1, far())
        .unwrap();
    // 100 + 50 body bytes + 2 rows * 128 bytes overhead
    assert_eq!(s.total_size(), 406);
}

#[test]
fn total_size_tracks_every_delete_path_and_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.db");
    let s = Store::open(&path).unwrap();
    s.insert_paste("aaaa0001", &[0u8; 100], "::1", 1, far())
        .unwrap();
    s.insert_paste("aaaa0002", &[0u8; 50], "203.0.113.5", 1, far())
        .unwrap();
    s.insert_paste("aaaa0003", &[0u8; 30], "::1", 1, 2).unwrap(); // expired
                                                                  // a slug conflict stores nothing, so it must not inflate the counter
    assert!(!s
        .insert_paste("aaaa0001", &[0u8; 999], "::1", 1, far())
        .unwrap());
    assert_eq!(s.total_size(), 100 + 50 + 30 + 3 * 128);
    assert!(s.delete_paste("aaaa0001").unwrap());
    assert_eq!(s.total_size(), 50 + 30 + 2 * 128);
    assert!(!s.delete_paste("aaaa0001").unwrap()); // missing: no debit
    assert_eq!(s.total_size(), 50 + 30 + 2 * 128);
    assert_eq!(s.delete_expired(200).unwrap(), 1);
    assert_eq!(s.total_size(), 50 + 128);
    let net: ipnet::IpNet = "203.0.113.0/24".parse().unwrap();
    assert_eq!(s.add_ban_with_purge(&net, None, None).unwrap(), 1);
    assert_eq!(s.total_size(), 0);
    // a fresh open re-seeds from the real SUM, not a stale cache
    s.insert_paste("bbbb0001", &[0u8; 10], "::1", 1, far())
        .unwrap();
    drop(s);
    let s = Store::open(&path).unwrap();
    assert_eq!(s.total_size(), 10 + 128);
}

#[test]
fn bans_roundtrip_and_skip_garbage_rows() {
    let (_d, s) = temp_store();
    s.add_ban("203.0.113.0/24", Some("spam"), None).unwrap();
    s.add_ban("2001:db8::/32", None, Some(9999)).unwrap();
    s.add_ban("not-a-cidr", None, None).unwrap();
    let bans = s.bans().unwrap();
    assert_eq!(bans.len(), 2);
    assert!(bans
        .iter()
        .any(|(n, u)| n.to_string() == "203.0.113.0/24" && u.is_none()));
    assert!(bans
        .iter()
        .any(|(n, u)| n.to_string() == "2001:db8::/32" && *u == Some(9999)));
}

#[test]
fn fresh_store_has_incremental_auto_vacuum_and_wal_journal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.db");
    let _s = Store::open(&path).unwrap();
    // A second connection to the same file reads back the pragmas that
    // Store::open wrote into the DB header, proof the ordering actually
    // took effect, not just that pragma_update returned Ok.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let auto_vacuum: i64 = conn
        .pragma_query_value(None, "auto_vacuum", |r| r.get(0))
        .unwrap();
    assert_eq!(auto_vacuum, 2, "auto_vacuum should be INCREMENTAL (2)");
    let journal_mode: String = conn
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap();
    assert_eq!(journal_mode, "wal");
}

#[test]
fn exists_reflects_presence_without_fetching_body() {
    let (_d, s) = temp_store();
    assert!(!s.exists("nosuch00").unwrap());
    s.insert_paste("existsok", b"x", "::1", 1, far()).unwrap();
    assert!(s.exists("existsok").unwrap());
}

#[test]
fn reopen_preserves_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.db");
    {
        let s = Store::open(&path).unwrap();
        s.insert_paste("dddddddd", b"persist", "::1", 1, far())
            .unwrap();
    }
    let s = Store::open(&path).unwrap();
    assert_eq!(s.get_paste("dddddddd").unwrap().unwrap(), b"persist");
}

#[test]
fn expired_pastes_are_not_served() {
    let (_d, s) = temp_store();
    s.insert_paste("stale000", b"old", "::1", 1, 2).unwrap(); // expired long ago
    s.insert_paste("fresh000", b"new", "::1", 1, far()).unwrap();
    assert_eq!(s.get_paste("stale000").unwrap(), None);
    assert!(!s.exists("stale000").unwrap());
    assert_eq!(s.get_paste("fresh000").unwrap().unwrap(), b"new");
    assert!(s.exists("fresh000").unwrap());
}

#[test]
fn delete_expired_removes_exactly_the_expired_rows() {
    let (_d, s) = temp_store();
    s.insert_paste("old00001", b"a", "::1", 1, 100).unwrap();
    s.insert_paste("old00002", b"b", "::1", 1, 200).unwrap();
    s.insert_paste("new00001", b"c", "::1", 1, far()).unwrap();
    assert_eq!(s.delete_expired(200).unwrap(), 2); // expires_at <= now goes
    assert!(s.exists("new00001").unwrap());
    assert_eq!(s.delete_expired(200).unwrap(), 0); // idempotent
    s.incremental_vacuum().unwrap(); // must not error after deletes
}

#[test]
fn delete_expired_sweeps_more_rows_than_one_batch() {
    // 10_005 expired rows force the batched reaper through the loop-again
    // path (full 10_000-row batch) and the final short batch.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.db");
    drop(Store::open(&path).unwrap()); // create the schema
    {
        let mut conn = rusqlite::Connection::open(&path).unwrap();
        let tx = conn.transaction().unwrap();
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO paste (slug, body, size, created_at, expires_at)
                     VALUES (?1, x'61', 1, 1, 2)",
                )
                .unwrap();
            for i in 0..10_005 {
                stmt.execute([format!("bulk{i:05}")]).unwrap();
            }
        }
        tx.commit().unwrap();
    }
    let s = Store::open(&path).unwrap();
    assert_eq!(s.total_size(), 10_005 * (1 + 128));
    assert_eq!(s.delete_expired(100).unwrap(), 10_005);
    assert_eq!(s.total_size(), 0);
    assert_eq!(s.delete_expired(100).unwrap(), 0); // idempotent
}

#[test]
fn make_room_evicts_oldest_first_and_only_enough() {
    let (_d, s) = temp_store();
    s.insert_paste("old00001", &[0u8; 100], "::1", 100, far())
        .unwrap();
    s.insert_paste("mid00001", &[0u8; 100], "::1", 200, far())
        .unwrap();
    s.insert_paste("new00001", &[0u8; 100], "::1", 300, far())
        .unwrap();
    // total 684; fitting 228 more under a 700 quota leaves a 212 deficit,
    // which the single oldest row (228 freed) covers: no over-eviction.
    // created_at of epoch 100 is far past retention/2, so all are fair game.
    assert_eq!(
        s.make_room(228, 700, 30).unwrap(),
        RoomOutcome::Fits {
            evicted: 1,
            bytes: 228
        }
    );
    assert!(!s.exists("old00001").unwrap());
    assert!(s.exists("mid00001").unwrap());
    assert!(s.exists("new00001").unwrap());
    assert_eq!(s.total_size(), 456);
    // already fits: nothing evicted
    assert_eq!(
        s.make_room(228, 700, 30).unwrap(),
        RoomOutcome::Fits {
            evicted: 0,
            bytes: 0
        }
    );
    assert_eq!(s.total_size(), 456);
}

#[test]
fn make_room_reseeds_so_cli_deletes_never_cause_phantom_eviction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.db");
    let server = Store::open(&path).unwrap();
    server
        .insert_paste("old00001", &[0u8; 100], "::1", 100, far())
        .unwrap();
    server
        .insert_paste("mid00001", &[0u8; 100], "::1", 200, far())
        .unwrap();
    server
        .insert_paste("new00001", &[0u8; 100], "::1", 300, far())
        .unwrap();
    // `scrip rm` runs in a separate process with its own Store handle: the
    // server's cached total (684) no longer matches the real 456.
    let cli = Store::open(&path).unwrap();
    assert!(cli.delete_paste("old00001").unwrap());
    assert_eq!(server.total_size(), 684, "the drift under test");
    // Real usage is 456: 228 more fit under a 700 quota with no eviction at
    // all, but the stale cache claims a deficit that would evict mid00001.
    assert_eq!(
        server.make_room(228, 700, 30).unwrap(),
        RoomOutcome::Fits {
            evicted: 0,
            bytes: 0
        }
    );
    assert!(server.exists("mid00001").unwrap());
    assert!(server.exists("new00001").unwrap());
    assert_eq!(server.total_size(), 456, "make_room must re-seed the cache");
    // Reaper drift hygiene: delete_expired re-seeds even with nothing to do.
    assert!(cli.delete_paste("mid00001").unwrap());
    assert_eq!(server.total_size(), 456);
    assert_eq!(server.delete_expired(1).unwrap(), 0);
    assert_eq!(server.total_size(), 228);
}

#[test]
fn make_room_refuses_rather_than_evict_fresh_pastes() {
    let (_d, s) = temp_store();
    let now = far() - 86_400;
    s.insert_paste("fresh001", &[0u8; 100], "::1", now, far())
        .unwrap();
    s.insert_paste("fresh002", &[0u8; 100], "::1", now, far())
        .unwrap();
    // 456 used; another 228 under a 500 quota needs eviction, but nothing
    // is older than retention/2: refuse the write, destroy nothing.
    assert_eq!(s.make_room(228, 500, 30).unwrap(), RoomOutcome::Full);
    assert!(s.exists("fresh001").unwrap());
    assert!(s.exists("fresh002").unwrap());
    // An old paste is fair game: evicting it alone makes the write fit,
    // and the fresh ones still survive.
    s.insert_paste("old00001", &[0u8; 100], "::1", 100, far())
        .unwrap();
    assert_eq!(
        s.make_room(228, 700, 30).unwrap(),
        RoomOutcome::Fits {
            evicted: 1,
            bytes: 228
        }
    );
    assert!(!s.exists("old00001").unwrap());
    assert!(s.exists("fresh001").unwrap());
    assert!(s.exists("fresh002").unwrap());
}

#[test]
fn takedown_scrub_leaves_no_body_bytes_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.db");
    let wal = dir.path().join("t.db-wal");
    let s = Store::open(&path).unwrap();
    let marker: &[u8] = b"CARVE-ME-7f3a9c1d-DISTINCTIVE-BODY-BYTES";
    s.insert_paste("takedown", marker, "::1", 1, far()).unwrap();
    let on_disk = |p: &std::path::Path| {
        std::fs::read(p)
            .map(|d| d.windows(marker.len()).any(|w| w == marker))
            .unwrap_or(false)
    };
    // sanity: the bytes really hit the disk before the takedown, otherwise
    // the absence assertions below prove nothing
    assert!(on_disk(&path) || on_disk(&wal), "marker never hit the disk");
    assert!(s.delete_paste("takedown").unwrap());
    s.scrub().unwrap();
    assert!(
        !on_disk(&path),
        "deleted body still carvable from the db file"
    );
    assert!(!on_disk(&wal), "deleted body still carvable from the wal");
}

#[test]
fn delete_paste_reports_presence() {
    let (_d, s) = temp_store();
    s.insert_paste("gone0001", b"x", "::1", 1, far()).unwrap();
    assert!(s.delete_paste("gone0001").unwrap());
    assert!(!s.delete_paste("gone0001").unwrap());
    assert_eq!(s.get_paste("gone0001").unwrap(), None);
}

#[test]
fn remove_ban_reports_presence() {
    let (_d, s) = temp_store();
    s.add_ban("203.0.113.0/24", None, None).unwrap();
    assert!(s.remove_ban("203.0.113.0/24").unwrap());
    assert!(!s.remove_ban("203.0.113.0/24").unwrap());
}

#[test]
fn ban_rows_returns_raw_rows() {
    let (_d, s) = temp_store();
    s.add_ban("203.0.113.0/24", Some("spam"), Some(999))
        .unwrap();
    let rows = s.ban_rows().unwrap();
    assert_eq!(
        rows,
        vec![("203.0.113.0/24".into(), Some("spam".into()), Some(999))]
    );
}

#[test]
fn extend_ban_never_shortens_an_existing_ban() {
    let (_d, s) = temp_store();
    // permanent operator ban survives an auto-ban strike, reason kept
    s.add_ban("203.0.113.0/24", Some("operator"), None).unwrap();
    s.extend_ban("203.0.113.0/24", Some("auto: rate abuse"), Some(1000))
        .unwrap();
    assert_eq!(
        s.ban_rows().unwrap(),
        vec![("203.0.113.0/24".into(), Some("operator".into()), None)]
    );
    // a longer auto-ban followed by a shorter one keeps the longer until
    s.extend_ban("198.51.100.0/24", Some("auto: rate abuse"), Some(2000))
        .unwrap();
    s.extend_ban("198.51.100.0/24", Some("auto: rate abuse"), Some(500))
        .unwrap();
    let row = (
        "198.51.100.0/24".into(),
        Some("auto: rate abuse".into()),
        Some(2000),
    );
    assert!(s.ban_rows().unwrap().contains(&row));
    // and a genuinely longer strike still extends
    s.extend_ban("198.51.100.0/24", Some("auto: rate abuse"), Some(3000))
        .unwrap();
    let row = (
        "198.51.100.0/24".into(),
        Some("auto: rate abuse".into()),
        Some(3000),
    );
    assert!(s.ban_rows().unwrap().contains(&row));
}

#[test]
fn cli_add_ban_keeps_overwrite_semantics() {
    // The operator stays authoritative: add_ban may shorten or even demote
    // a permanent ban, unlike the auto-ban path's extend_ban.
    let (_d, s) = temp_store();
    s.add_ban("203.0.113.0/24", Some("perm"), None).unwrap();
    s.add_ban("203.0.113.0/24", Some("short"), Some(100))
        .unwrap();
    assert_eq!(
        s.ban_rows().unwrap(),
        vec![("203.0.113.0/24".into(), Some("short".into()), Some(100))]
    );
}

#[test]
fn ban_with_purge_is_atomic_and_scoped() {
    let (_d, s) = temp_store();
    s.insert_paste("inside01", b"a", "203.0.113.5", 1, far())
        .unwrap();
    s.insert_paste("inside02", b"b", "203.0.113.99", 1, far())
        .unwrap();
    s.insert_paste("outside1", b"c", "198.51.100.1", 1, far())
        .unwrap();
    s.insert_paste("weird001", b"d", "not-an-ip", 1, far())
        .unwrap(); // unparseable: never purged
    let net: ipnet::IpNet = "203.0.113.0/24".parse().unwrap();
    let purged = s.add_ban_with_purge(&net, Some("abuse"), None).unwrap();
    assert_eq!(purged, 2);
    assert!(!s.exists("inside01").unwrap());
    assert!(!s.exists("inside02").unwrap());
    assert!(s.exists("outside1").unwrap());
    assert!(s.exists("weird001").unwrap());
    assert_eq!(s.ban_rows().unwrap().len(), 1);
}

#[test]
fn delete_expired_bans_leaves_permanent_ones() {
    let (_d, s) = temp_store();
    s.add_ban("203.0.113.0/24", None, Some(100)).unwrap(); // expired
    s.add_ban("198.51.100.0/24", None, None).unwrap(); // permanent
    s.add_ban("192.0.2.0/24", None, Some(far())).unwrap(); // future
    assert_eq!(s.delete_expired_bans(200).unwrap(), 1);
    assert_eq!(s.ban_rows().unwrap().len(), 2);
}

#[test]
fn record_offense_upserts_and_returns_the_running_count() {
    let (_d, s) = temp_store();
    assert_eq!(s.record_offense("203.0.113.9", 100).unwrap(), 1);
    assert_eq!(s.record_offense("203.0.113.9", 200).unwrap(), 2);
    assert_eq!(s.record_offense("203.0.113.9", 300).unwrap(), 3);
    // a different key starts its own count
    assert_eq!(s.record_offense("198.51.100.1", 300).unwrap(), 1);
}

#[test]
fn forget_stale_offenses_boundary() {
    let (_d, s) = temp_store();
    s.record_offense("203.0.113.9", 100).unwrap();
    s.record_offense("198.51.100.1", 200).unwrap();
    // cutoff equal to last_seen is not forgotten (< cutoff, not <=)
    assert_eq!(s.forget_stale_offenses(100).unwrap(), 0);
    assert_eq!(s.forget_stale_offenses(101).unwrap(), 1);
    assert_eq!(s.forget_stale_offenses(201).unwrap(), 1);
}

#[test]
fn count_by_source_key_counts_live_pastes_only() {
    let (_d, s) = temp_store();
    s.insert_paste("live0001", b"a", "203.0.113.5", 1, far())
        .unwrap();
    s.insert_paste("live0002", b"b", "203.0.113.5", 1, far())
        .unwrap();
    s.insert_paste("dead0001", b"c", "203.0.113.5", 1, 2)
        .unwrap(); // expired
    s.insert_paste("other001", b"d", "198.51.100.1", 1, far())
        .unwrap();
    assert_eq!(s.count_by_source_key("203.0.113.5").unwrap(), 2);
    assert_eq!(s.count_by_source_key("198.51.100.1").unwrap(), 1);
    assert_eq!(s.count_by_source_key("192.0.2.1").unwrap(), 0);
}

#[test]
fn count_by_source_key48_spans_every_64_in_the_48() {
    let (_d, s) = temp_store();
    // The /48 network address "2001:db8:1::" omits the fourth group, so the
    // query must cover it with an exact match alongside the prefix range.
    s.insert_paste("aaaa0001", b"a", "2001:db8:1:0:9::1", 1, far())
        .unwrap();
    s.insert_paste("aaaa0002", b"b", "2001:db8:1:2::1", 1, far())
        .unwrap();
    s.insert_paste("aaaa0003", b"c", "2001:db8:1:2:ffff::1", 1, far())
        .unwrap(); // same /64 as aaaa0002: still one row each
    s.insert_paste("aaaa0004", b"d", "2001:db8:2::1", 1, far())
        .unwrap(); // different /48
    s.insert_paste("aaaa0005", b"e", "2001:db8:1:3::1", 1, 2)
        .unwrap(); // expired
                   // adjacent prefixes a sloppy range bound would sweep in: their keys
                   // ("2001:db8:10:2::", "2001:db8:1f::") sort right around the
                   // "2001:db8:1:" prefix without carrying it
    s.insert_paste("aaaa0006", b"f", "2001:db8:10:2::1", 1, far())
        .unwrap();
    s.insert_paste("aaaa0007", b"g", "2001:db8:1f::1", 1, far())
        .unwrap();
    let key48: std::net::Ipv6Addr = "2001:db8:1::".parse().unwrap();
    assert_eq!(s.count_by_source_key48(key48).unwrap(), 3);
    let other: std::net::Ipv6Addr = "2001:db9::".parse().unwrap();
    assert_eq!(s.count_by_source_key48(other).unwrap(), 0);
}

#[test]
fn count_sibling_autobans48_counts_active_auto_64s_only() {
    let (_d, s) = temp_store();
    let auto = Some("auto: rate abuse");
    s.extend_ban("2001:db8:1:1::/64", auto, Some(1000)).unwrap();
    s.extend_ban("2001:db8:1::/64", auto, Some(1000)).unwrap(); // compressed display form
    s.extend_ban("2001:db8:1:2::/64", auto, Some(10)).unwrap(); // expired at now=500
    s.extend_ban("2001:db8:1:3::/64", Some("operator"), Some(1000))
        .unwrap(); // not an auto-ban
    s.extend_ban("2001:db8:2:1::/64", auto, Some(1000)).unwrap(); // other /48
    s.extend_ban("2001:db8:1::/48", auto, Some(1000)).unwrap(); // not a /64
    let key48: std::net::Ipv6Addr = "2001:db8:1::".parse().unwrap();
    // the /64 being banned right now is excluded from its own sibling count
    assert_eq!(
        s.count_sibling_autobans48(key48, "2001:db8:1:1::/64", 500)
            .unwrap(),
        1
    );
    assert_eq!(
        s.count_sibling_autobans48(key48, "2001:db8:1:ffff::/64", 500)
            .unwrap(),
        2
    );
}

#[test]
fn open_rewrites_mapped_ban_rows_to_matching_v4() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.db");
    {
        let s = Store::open(&path).unwrap();
        s.add_ban("::ffff:203.0.113.0/120", Some("spam"), Some(9999))
            .unwrap();
        s.add_ban("2001:db8::/32", None, None).unwrap(); // genuine v6: untouched
    }
    let s = Store::open(&path).unwrap();
    let rows = s.ban_rows().unwrap();
    assert!(
        rows.contains(&("203.0.113.0/24".into(), Some("spam".into()), Some(9999))),
        "mapped row must become its v4 equivalent: {rows:?}"
    );
    assert!(
        !rows.iter().any(|(c, _, _)| c.starts_with("::ffff:")),
        "no mapped row may survive: {rows:?}"
    );
    assert!(rows.iter().any(|(c, _, _)| c == "2001:db8::/32"));
    // the rewritten row matches a canonical v4 address again
    let bl = BanList::new();
    bl.replace(s.bans().unwrap());
    assert!(bl.is_banned("203.0.113.9".parse().unwrap(), 0));
    // rerunnable: another open changes nothing
    drop(s);
    assert_eq!(Store::open(&path).unwrap().ban_rows().unwrap(), rows);
}

#[test]
fn open_drops_auto_zero64_rows_but_keeps_operator_ones() {
    let dir = tempfile::tempdir().unwrap();
    // an auto ::/64 row born of the old truncation bug: gone
    let path = dir.path().join("auto.db");
    {
        let s = Store::open(&path).unwrap();
        s.add_ban("::/64", Some("auto: rate abuse"), Some(9999))
            .unwrap();
    }
    let s = Store::open(&path).unwrap();
    assert!(
        s.ban_rows().unwrap().is_empty(),
        "the bogus auto ::/64 row must be dropped"
    );
    // an operator-written ::/64: survives
    let path = dir.path().join("manual.db");
    {
        let s = Store::open(&path).unwrap();
        s.add_ban("::/64", Some("operator"), None).unwrap();
    }
    let s = Store::open(&path).unwrap();
    assert_eq!(
        s.ban_rows().unwrap(),
        vec![("::/64".into(), Some("operator".into()), None)]
    );
}

#[test]
fn migration_adds_and_backfills_source_key_on_an_old_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v1.db");
    {
        // Create a pre-migration schema without source_key.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE paste (
              slug       TEXT    PRIMARY KEY,
              body       BLOB    NOT NULL,
              size       INTEGER NOT NULL,
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              source_ip  TEXT,
              hits       INTEGER NOT NULL DEFAULT 0
            ) STRICT;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO paste (slug, body, size, created_at, expires_at, source_ip)
             VALUES ('oldslug1', x'61', 1, 1, ?1, '203.0.113.5')",
            [far()],
        )
        .unwrap();
    }
    let s = Store::open(&path).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    assert!(conn
        .prepare("PRAGMA table_info(paste)")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .filter_map(Result::ok)
        .any(|n| n == "source_key"));
    let key: String = conn
        .query_row(
            "SELECT source_key FROM paste WHERE slug = 'oldslug1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(key, "203.0.113.5");
    assert_eq!(s.count_by_source_key("203.0.113.5").unwrap(), 1);
}

#[test]
fn migration_resumes_a_half_applied_backfill() {
    // Simulate an interrupted migration: source_key exists but is NULL for
    // a row with a known source_ip. Store::open must finish the backfill.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("half.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE paste (
              slug       TEXT    PRIMARY KEY,
              body       BLOB    NOT NULL,
              size       INTEGER NOT NULL,
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              source_ip  TEXT,
              hits       INTEGER NOT NULL DEFAULT 0
            ) STRICT;
             ALTER TABLE paste ADD COLUMN source_key TEXT;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO paste (slug, body, size, created_at, expires_at, source_ip, source_key)
             VALUES ('halfslug', x'61', 1, 1, ?1, '198.51.100.9', NULL)",
            [far()],
        )
        .unwrap();
    }
    let s = Store::open(&path).unwrap();
    assert_eq!(s.count_by_source_key("198.51.100.9").unwrap(), 1);
}

#[test]
fn burn_paste_claims_exactly_once_and_hides_from_plain_reads() {
    let (_d, s) = temp_store();
    s.insert_paste_opts("burn0001", b"secret", "::1", 1, far(), true, None)
        .unwrap();
    // the plain read path must never serve a burn row
    assert_eq!(s.get_paste("burn0001").unwrap(), None);
    assert_eq!(s.burn_status("burn0001").unwrap(), Some(true));
    assert_eq!(s.claim_burn("burn0001").unwrap().unwrap(), b"secret");
    assert_eq!(s.claim_burn("burn0001").unwrap(), None);
    assert_eq!(s.burn_status("burn0001").unwrap(), None);
}

#[test]
fn concurrent_burn_claims_yield_exactly_one_body() {
    let (_d, s) = temp_store();
    s.insert_paste_opts("race0001", b"x", "::1", 1, far(), true, None)
        .unwrap();
    let wins: usize = std::thread::scope(|scope| {
        (0..16)
            .map(|_| {
                let s = s.clone();
                scope.spawn(move || s.claim_burn("race0001").unwrap().is_some() as usize)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .sum()
    });
    assert_eq!(wins, 1);
}

#[test]
fn claim_burn_leaves_normal_pastes_alone() {
    let (_d, s) = temp_store();
    s.insert_paste("norm0001", b"keep", "::1", 1, far())
        .unwrap();
    assert_eq!(s.claim_burn("norm0001").unwrap(), None);
    assert_eq!(s.get_paste("norm0001").unwrap().unwrap(), b"keep");
    assert_eq!(s.burn_status("norm0001").unwrap(), Some(false));
}

#[test]
fn delete_by_token_needs_the_exact_hash() {
    let (_d, s) = temp_store();
    s.insert_paste_opts("tok00001", b"x", "::1", 1, far(), false, Some(b"hash-a"))
        .unwrap();
    s.insert_paste("old00001", b"y", "::1", 1, far()).unwrap(); // NULL hash
    assert!(!s.delete_by_token("tok00001", b"hash-b").unwrap());
    assert!(s.exists("tok00001").unwrap());
    // a NULL-hash row (pre-feature paste) matches no token at all
    assert!(!s.delete_by_token("old00001", b"hash-a").unwrap());
    assert!(s.exists("old00001").unwrap());
    assert!(s.delete_by_token("tok00001", b"hash-a").unwrap());
    assert!(!s.exists("tok00001").unwrap());
    // deleting the same slug again is a non-event
    assert!(!s.delete_by_token("tok00001", b"hash-a").unwrap());
}

#[test]
fn burn_and_token_deletes_keep_the_size_cache_honest() {
    let (_d, s) = temp_store();
    let empty = s.total_size();
    s.insert_paste_opts("burn0001", &[0u8; 100], "::1", 1, far(), true, Some(b"h1"))
        .unwrap();
    s.insert_paste_opts("tok00001", &[0u8; 100], "::1", 1, far(), false, Some(b"h2"))
        .unwrap();
    assert!(s.total_size() > empty);
    s.claim_burn("burn0001").unwrap().unwrap();
    assert!(s.delete_by_token("tok00001", b"h2").unwrap());
    assert_eq!(s.total_size(), empty);
}

#[test]
fn paste_options_migration_upgrades_an_old_db() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE paste (
              slug       TEXT    PRIMARY KEY,
              body       BLOB    NOT NULL,
              size       INTEGER NOT NULL,
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              source_ip  TEXT,
              hits       INTEGER NOT NULL DEFAULT 0,
              source_key TEXT
            ) STRICT;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO paste (slug, body, size, created_at, expires_at, source_ip, source_key)
             VALUES ('oldpaste', x'61', 1, 1, ?1, '::1', '::1')",
            [far()],
        )
        .unwrap();
    }
    let s = Store::open(&path).unwrap();
    // the pre-feature row: not a burn paste, readable, deletable by no token
    assert_eq!(s.burn_status("oldpaste").unwrap(), Some(false));
    assert_eq!(s.get_paste("oldpaste").unwrap().unwrap(), b"a");
    assert!(!s.delete_by_token("oldpaste", b"anything").unwrap());
    // new-style rows work in the upgraded db
    s.insert_paste_opts("newburn1", b"b", "::1", 1, far(), true, Some(b"h"))
        .unwrap();
    assert_eq!(s.claim_burn("newburn1").unwrap().unwrap(), b"b");
    // reopening reruns the migration harmlessly
    drop(s);
    Store::open(&path).unwrap();
}

/// Old body frames remain in the WAL until a checkpoint, even with
/// secure_delete. Check the periodic checkpoint used for routine deletes;
/// `rm` and `ban add --purge` also run the full scrub.
#[test]
fn routine_deletes_leave_no_body_bytes_in_the_wal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.db");
    let wal = dir.path().join("t.db-wal");
    let s = Store::open(&path).unwrap();
    let on_disk = |p: &std::path::Path, m: &[u8]| {
        std::fs::read(p)
            .map(|d| d.windows(m.len()).any(|w| w == m))
            .unwrap_or(false)
    };
    let burned: &[u8] = b"BURNED-9a2f1c-DISTINCTIVE-BODY";
    let revoked: &[u8] = b"REVOKED-4c8e7b-DISTINCTIVE-BODY";
    let expired: &[u8] = b"EXPIRED-1b7d3e-DISTINCTIVE-BODY";
    s.insert_paste_opts("burnrow0", burned, "::1", 1, far(), true, None)
        .unwrap();
    s.insert_paste_opts("tokenrow", revoked, "::1", 1, far(), false, Some(b"hash"))
        .unwrap();
    s.insert_paste("expirerw", expired, "::1", 1, 2).unwrap();

    // sanity: the bodies really reach the disk, or the assertions below
    // would pass against a database that never wrote anything
    assert!(
        on_disk(&path, burned) || on_disk(&wal, burned),
        "marker never hit the disk"
    );

    s.claim_burn("burnrow0").unwrap().unwrap();
    assert!(s.delete_by_token("tokenrow", b"hash").unwrap());
    s.delete_expired(far()).unwrap();
    assert!(
        s.checkpoint_wal().unwrap(),
        "nothing else holds this database, so the checkpoint must complete"
    );

    for (what, marker) in [
        ("burned", burned),
        ("token-deleted", revoked),
        ("expired", expired),
    ] {
        assert!(!on_disk(&path, marker), "{what} body still in the db file");
        assert!(!on_disk(&wal, marker), "{what} body still in the wal");
    }
}

#[test]
fn make_room_evicts_expired_rows_before_the_age_floor() {
    // Expired rows are eligible for eviction even within the age floor.
    // Reclaiming them lets uploads proceed without waiting for the reaper.
    let (_d, s) = temp_store();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // A fresh row (created now, so well inside the age floor) that has
    // already expired.
    assert!(s
        .insert_paste("expired0", &vec![b'x'; 4096], "::1", now, now - 1)
        .unwrap());
    let used = s.total_size();
    assert!(used > 4096);

    // A quota with no headroom: without the expired row, nothing fits.
    let outcome = s.make_room(4096, used, 30).unwrap();
    assert!(
        matches!(outcome, RoomOutcome::Fits { evicted: 1, .. }),
        "expected the expired row to be evicted, got {outcome:?}"
    );
    assert_eq!(s.get_paste("expired0").unwrap(), None);
}

#[test]
fn a_live_paste_inside_the_age_floor_is_still_never_evicted() {
    // Quota pressure must not evict live pastes within the age floor.
    let (_d, s) = temp_store();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(s
        .insert_paste("liveone0", &vec![b'x'; 4096], "::1", now, far())
        .unwrap());
    let used = s.total_size();
    assert_eq!(s.make_room(4096, used, 30).unwrap(), RoomOutcome::Full);
    assert!(s.get_paste("liveone0").unwrap().is_some());
}

#[test]
fn burning_a_paste_restarts_the_wal_immediately() {
    // A burn read should checkpoint immediately when possible, removing old
    // body frames without waiting for the reaper.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.db");
    let s = Store::open(&path).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let secret = vec![b'S'; 64 * 1024];
    assert!(s
        .insert_paste_opts("burnme00", &secret, "::1", now, far(), true, None)
        .unwrap());

    let wal = path.with_extension("db-wal");
    let before = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    assert!(before > 0, "expected a populated wal to begin with");

    assert_eq!(s.claim_burn("burnme00").unwrap().unwrap(), secret);

    let after = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    assert_eq!(after, 0, "the wal must be truncated by the burn itself");
}

#[test]
fn a_token_delete_restarts_the_wal_immediately() {
    // Token deletes should also checkpoint immediately when possible.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.db");
    let s = Store::open(&path).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // delete_by_token only ever compares the stored blob to the presented
    // one, so any distinct byte string stands in for the real SHA-256.
    let token_hash: &[u8] = b"stand-in for the token hash";
    let secret = vec![b'T'; 64 * 1024];
    assert!(s
        .insert_paste_opts(
            "tokendel",
            &secret,
            "::1",
            now,
            far(),
            false,
            Some(token_hash)
        )
        .unwrap());

    let wal = path.with_extension("db-wal");
    assert!(
        std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0) > 0,
        "expected a populated wal to begin with"
    );

    assert!(s.delete_by_token("tokendel", token_hash).unwrap());
    assert_eq!(
        std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0),
        0,
        "the wal must be truncated by the delete itself"
    );
    // A wrong token still deletes nothing.
    assert!(!s.delete_by_token("tokendel", b"other").unwrap());
}
