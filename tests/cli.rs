use std::process::Command;

mod support;
use support::far;

fn scrip(args: &[&str], db: &std::path::Path) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_scrip"))
        .args(args)
        .arg("--db")
        .arg(db)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn seed(db: &std::path::Path) -> scrip::store::Store {
    scrip::store::Store::open(db).unwrap()
}

#[test]
fn ban_add_list_rm_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("c.db");
    seed(&db);
    let (ok, out, _) = scrip(&["ban", "add", "203.0.113.0/24", "--reason", "spam"], &db);
    assert!(ok, "{out}");
    let (ok, out, _) = scrip(&["ban", "list"], &db);
    assert!(ok);
    assert!(out.contains("203.0.113.0/24"));
    assert!(out.contains("spam"));
    let (ok, _, _) = scrip(&["ban", "rm", "203.0.113.0/24"], &db);
    assert!(ok);
    let (ok, _, err) = scrip(&["ban", "rm", "203.0.113.0/24"], &db);
    assert!(!ok, "removing a missing ban must exit nonzero");
    assert!(err.contains("no such ban"));
}

#[test]
fn ban_add_for_duration_sets_until() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("c.db");
    let s = seed(&db);
    let before = far() - 86_400; // now
    let (ok, _, _) = scrip(&["ban", "add", "198.51.100.0/24", "--for", "30d"], &db);
    assert!(ok);
    let rows = s.ban_rows().unwrap();
    let until = rows[0].2.expect("until must be set");
    let expect = before + 30 * 86_400;
    assert!(
        (until - expect).abs() < 120,
        "until {until} vs expected {expect}"
    );
}

#[test]
fn ban_add_purge_removes_matching_pastes() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("c.db");
    let s = seed(&db);
    s.insert_paste("victim01", b"a", "203.0.113.9", 1, far())
        .unwrap();
    s.insert_paste("keeper01", b"b", "198.51.100.9", 1, far())
        .unwrap();
    let (ok, out, _) = scrip(&["ban", "add", "203.0.113.0/24", "--purge"], &db);
    assert!(ok);
    assert!(out.contains("purged 1"), "{out}");
    assert!(!s.exists("victim01").unwrap());
    assert!(s.exists("keeper01").unwrap());
}

#[test]
fn ban_export_nft_emits_both_families_and_skips_expired() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("c.db");
    let s = seed(&db);
    s.add_ban("203.0.113.0/24", None, None).unwrap();
    s.add_ban("2001:db8::/32", None, None).unwrap();
    s.add_ban("192.0.2.0/24", None, Some(10)).unwrap(); // expired long ago
    let (ok, out, _) = scrip(&["ban", "export"], &db);
    assert!(ok);
    assert!(out.contains("add element inet scrip scrip_bans4 { 203.0.113.0/24 }"));
    assert!(out.contains("add element inet scrip scrip_bans6 { 2001:db8::/32 }"));
    assert!(
        !out.contains("192.0.2.0/24"),
        "expired ban exported:\n{out}"
    );
}

#[test]
fn rm_deletes_one_paste() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("c.db");
    let s = seed(&db);
    s.insert_paste("takedown", b"bad", "::1", 1, far()).unwrap();
    let (ok, _, _) = scrip(&["rm", "takedown"], &db);
    assert!(ok);
    assert!(!s.exists("takedown").unwrap());
    let (ok, _, err) = scrip(&["rm", "takedown"], &db);
    assert!(!ok);
    assert!(err.contains("no such paste"));
}

#[test]
fn gc_sweeps_expired_rows() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("c.db");
    let s = seed(&db);
    s.insert_paste("dead0001", b"x", "::1", 1, 2).unwrap();
    s.insert_paste("live0001", b"y", "::1", 1, far()).unwrap();
    let (ok, out, _) = scrip(&["gc"], &db);
    assert!(ok);
    assert!(out.contains("removed 1 expired pastes"), "{out}");
    assert!(s.exists("live0001").unwrap());
    assert!(!s.exists("dead0001").unwrap());
}

#[test]
fn gc_on_nonexistent_db_is_a_clean_error() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("missing.db"); // deliberately never seeded
    let (ok, _, err) = scrip(&["gc"], &db);
    assert!(!ok);
    assert!(err.contains("no database"), "{err}");
}

#[test]
fn bad_cidr_is_a_clean_error() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("c.db");
    seed(&db);
    let (ok, _, err) = scrip(&["ban", "add", "not-a-cidr"], &db);
    assert!(!ok);
    assert!(!err.is_empty());
}

#[test]
fn bad_duration_unit_is_a_clean_error_not_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("c.db");
    seed(&db);
    let (ok, _, err) = scrip(&["ban", "add", "1.2.3.0/24", "--for", "30д"], &db);
    assert!(!ok);
    assert!(!err.is_empty());
    assert!(!err.contains("panicked"), "{err}");
}

#[test]
fn duration_overflow_is_a_clean_error_not_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("c.db");
    seed(&db);
    let (ok, _, err) = scrip(
        &["ban", "add", "1.2.3.0/24", "--for", "9999999999999999d"],
        &db,
    );
    assert!(!ok);
    assert!(!err.is_empty());
    assert!(!err.contains("panicked"), "{err}");
}

#[test]
fn ban_rm_strips_host_bits_to_match_add() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("c.db");
    seed(&db);
    let (ok, out, _) = scrip(&["ban", "add", "203.0.113.9/24"], &db);
    assert!(ok, "{out}");
    let (ok, _, err) = scrip(&["ban", "rm", "203.0.113.0/24"], &db);
    assert!(ok, "{err}");
    let (ok, out, _) = scrip(&["ban", "list"], &db);
    assert!(ok);
    assert!(out.is_empty(), "{out}");
}

#[test]
fn ban_rm_matches_equivalent_cidr_spelling() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("c.db");
    let s = seed(&db);
    // Stored in canonical form, exactly as `ban add` (which parses through
    // ipnet::IpNet before storing) would have written it.
    s.add_ban("2001:db8::/32", None, None).unwrap();
    let (ok, _, err) = scrip(&["ban", "rm", "2001:db8:0::/32"], &db);
    assert!(ok, "{err}");
}

#[test]
fn rm_takes_an_encryption_token_or_the_stored_id() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("c.db");
    let s = seed(&db);

    // a takedown request arrives as the URL, which carries the token
    let token = scrip::crypto::token();
    let id = scrip::crypto::token_id(&token);
    s.insert_paste(&id, &scrip::crypto::seal(&token, b"bad"), "::1", 1, far())
        .unwrap();
    let (ok, out, _) = scrip(&["rm", &token], &db);
    assert!(ok, "{out}");
    assert!(!s.exists(&id).unwrap());

    // the id from a log line works just as well
    let token = scrip::crypto::token();
    let id = scrip::crypto::token_id(&token);
    s.insert_paste(&id, &scrip::crypto::seal(&token, b"bad"), "::1", 1, far())
        .unwrap();
    let (ok, out, _) = scrip(&["rm", &id], &db);
    assert!(ok, "{out}");
    assert!(!s.exists(&id).unwrap());

    // a token for no paste still exits nonzero
    let (ok, _, err) = scrip(&["rm", &scrip::crypto::token()], &db);
    assert!(!ok);
    assert!(err.contains("no such paste"));
}

#[test]
fn ban_export_carries_a_timeout_so_the_kernel_expires_it() {
    // The export only ever adds elements and nothing ever removes them, so
    // an untimed element outlives its row: a 30-minute auto-ban would keep
    // dropping the source until someone reloaded the ruleset by hand.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("c.db");
    seed(&db);
    let (ok, _, err) = scrip(&["ban", "add", "203.0.113.0/24", "--for", "30m"], &db);
    assert!(ok, "{err}");
    let (ok, _, err) = scrip(&["ban", "add", "2001:db8::/32"], &db);
    assert!(ok, "{err}");

    let (ok, out, err) = scrip(&["ban", "export"], &db);
    assert!(ok, "{err}");

    let timed = out
        .lines()
        .find(|l| l.contains("203.0.113.0/24"))
        .unwrap_or_else(|| panic!("no v4 element in: {out}"));
    assert!(timed.contains("scrip_bans4"), "{timed}");
    let secs: i64 = timed
        .rsplit("timeout ")
        .next()
        .unwrap()
        .trim_end_matches(|c: char| c == '}' || c.is_whitespace())
        .trim_end_matches('s')
        .parse()
        .unwrap_or_else(|_| panic!("no parseable timeout in: {timed}"));
    assert!((1..=1800).contains(&secs), "{timed}");

    // A permanent ban has nothing to expire and must not get one.
    let perm = out
        .lines()
        .find(|l| l.contains("2001:db8::/32"))
        .unwrap_or_else(|| panic!("no v6 element in: {out}"));
    assert!(perm.contains("scrip_bans6"), "{perm}");
    assert!(!perm.contains("timeout"), "{perm}");
}

#[test]
fn ban_export_without_a_database_is_an_empty_success() {
    // scrip-firewall.service runs this at boot, before scrip has ever
    // started and created the database. No bans is the right answer there.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("not-yet.db");
    let (ok, out, err) = scrip(&["ban", "export"], &db);
    assert!(ok, "{err}");
    assert_eq!(out, "");
    assert!(!db.exists(), "export must not create the database");

    // Every other verb still refuses a path that does not exist, which is
    // what catches a typo.
    let (ok, _, err) = scrip(&["ban", "list"], &db);
    assert!(!ok);
    assert!(err.contains("no database at"), "{err}");
}

#[test]
fn ban_export_clamps_a_timeout_nft_would_reject() {
    // nft's per-element ceiling is 99,999,999s, and `nft -f` is atomic: one
    // oversized element fails the whole file and leaves the ban sets empty,
    // taking every valid ban with it. `ban add --for 3650d` reaches that
    // ceiling, and so does a boot before the clock is synced.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("c.db");
    seed(&db);
    let (ok, _, err) = scrip(&["ban", "add", "198.51.100.0/24", "--for", "3650d"], &db);
    assert!(ok, "{err}");
    let (ok, out, err) = scrip(&["ban", "export"], &db);
    assert!(ok, "{err}");
    assert!(
        out.contains("timeout 99999999s"),
        "an over-ceiling ban must clamp, got: {out}"
    );
}
