mod support;
use support::{far, get, post, request, serve};

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'";

#[tokio::test(flavor = "multi_thread")]
async fn post_then_raw_roundtrip_byte_exact() {
    let sv = serve(|_| {}).await;
    let payload = b"fn main() {}\n\x00\xff binary";
    let (st, _, body) = post(sv.port, payload, "");
    assert_eq!(st, 200);
    let url = String::from_utf8(body).unwrap();
    assert!(url.starts_with("https://t.local/"), "{url:?}");
    let slug = url.trim().rsplit('/').next().unwrap().to_string();
    let (st, h, raw) = get(sv.port, &format!("/raw/{slug}"));
    assert_eq!(st, 200);
    assert_eq!(h["content-type"], "text/plain; charset=utf-8");
    assert_eq!(raw, payload);
}

#[tokio::test(flavor = "multi_thread")]
async fn headers_are_exact_on_every_route() {
    let sv = serve(|c| c.max_paste_bytes = 100).await;
    let (_, _, body) = post(sv.port, b"x", "");
    let slug = String::from_utf8(body)
        .unwrap()
        .trim()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();

    for path in ["/", &format!("/{slug}"), "/nosuch1"] {
        let (_, h, _) = get(sv.port, path);
        assert_eq!(h["content-security-policy"], CSP, "CSP on {path}");
        assert_eq!(h["x-frame-options"], "DENY", "x-frame-options on {path}");
        assert_eq!(h["x-content-type-options"], "nosniff", "nosniff on {path}");
        assert!(h["content-type"].starts_with("text/html"), "html on {path}");
    }
    // every non-html route still gets nosniff
    for path in [
        format!("/raw/{slug}"),
        "/healthz".into(),
        "/assets/hl.js".into(),
        "/assets/nope.js".into(),
    ] {
        let (_, h, _) = get(sv.port, &path);
        assert_eq!(h["x-content-type-options"], "nosniff", "nosniff on {path}");
    }
    let (st, h, _) = get(sv.port, "/assets/hl.js");
    assert_eq!(st, 200);
    assert_eq!(h["cache-control"], "public, max-age=31536000, immutable");
    let (st, _, _) = get(sv.port, "/healthz");
    assert_eq!(st, 200);

    for path in [
        "/assets/nix.js",
        "/assets/theme-github-light.css",
        "/assets/theme-github-dark.css",
        "/assets/theme-solarized-light.css",
        "/assets/theme-solarized-dark.css",
        "/assets/theme-nord.css",
        "/assets/theme-catppuccin-latte.css",
        "/assets/theme-catppuccin-mocha.css",
    ] {
        let (st, h, _) = get(sv.port, path);
        assert_eq!(st, 200, "{path}");
        assert_eq!(
            h["cache-control"], "public, max-age=31536000, immutable",
            "cache-control on {path}"
        );
        assert_eq!(h["x-content-type-options"], "nosniff", "nosniff on {path}");
    }

    // fallback (no route matches) and rejection paths must carry nosniff too.
    let (st, h, _) = get(sv.port, "/a/b/c");
    assert_eq!(st, 404);
    assert_eq!(
        h["x-content-type-options"], "nosniff",
        "nosniff on 404 fallback"
    );

    let (st, h, _) = request(sv.port, "PUT / HTTP/1.0\r\nHost: t.local\r\n\r\n", b"");
    assert_eq!(st, 405);
    assert_eq!(h["x-content-type-options"], "nosniff", "nosniff on 405");

    let (st, h, _) = post(sv.port, &[7u8; 200], "");
    assert_eq!(st, 413);
    assert_eq!(h["x-content-type-options"], "nosniff", "nosniff on 413");
}

#[tokio::test(flavor = "multi_thread")]
async fn view_page_exists_and_missing_slug_is_404() {
    let sv = serve(|_| {}).await;
    let (_, _, body) = post(sv.port, b"hello", "");
    let slug = String::from_utf8(body)
        .unwrap()
        .trim()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    let (st, _, page) = get(sv.port, &format!("/{slug}"));
    assert_eq!(st, 200);
    let page = String::from_utf8(page).unwrap();
    assert!(page.contains("/assets/hl.js"));
    assert!(page.contains("/assets/view.js"));
    assert!(page.contains("/assets/nix.js"));
    // The bar the viewer script wires itself to. A shell that lost one of
    // these still renders, and the feature attached to it silently stops.
    for id in [
        "themepick",
        "facts",
        "langpick",
        "linestoggle",
        "wraptoggle",
        "rawlink",
        "download",
        "copy",
    ] {
        assert!(page.contains(&format!(r#"id="{id}""#)), "missing {id}");
    }
    let (st, _, _) = get(sv.port, "/zzzzzzzz");
    assert_eq!(st, 404);
    let (st, _, _) = get(sv.port, "/raw/zzzzzzzz");
    assert_eq!(st, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn oversize_post_is_413_and_empty_is_400() {
    let sv = serve(|c| c.max_paste_bytes = 100).await;
    let (st, _, _) = post(sv.port, &[7u8; 200], "");
    assert_eq!(st, 413);
    let (st, _, _) = post(sv.port, b"", "");
    assert_eq!(st, 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn post_rate_limit_and_xff_bucketing() {
    let sv = serve(|c| {
        c.rate_burst = 1.0;
        c.rate_per_minute = 0.6;
    })
    .await;
    // Peer is loopback, so XFF is trusted: two different forwarded clients
    // get their own buckets; the same client gets limited.
    let (st, _, _) = post(sv.port, b"a", "X-Forwarded-For: 203.0.113.5\r\n");
    assert_eq!(st, 200);
    let (st, _, body) = post(sv.port, b"b", "X-Forwarded-For: 203.0.113.5\r\n");
    assert_eq!(st, 429, "{:?}", String::from_utf8_lossy(&body));
    let (st, _, _) = post(sv.port, b"c", "X-Forwarded-For: 203.0.113.6\r\n");
    assert_eq!(st, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn banned_forwarded_client_gets_403() {
    let sv = serve(|_| {}).await;
    sv.ctx
        .bans
        .replace(vec![("203.0.113.0/24".parse().unwrap(), None)]);
    let (st, _, _) = post(sv.port, b"x", "X-Forwarded-For: 203.0.113.9\r\n");
    assert_eq!(st, 403);
    let (st, _, _) = post(sv.port, b"x", "X-Forwarded-For: 198.51.100.9\r\n");
    assert_eq!(st, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn quota_full_is_507() {
    // 507 covers a paste that could never fit: body plus the 128-byte row
    // overhead above the whole quota. A merely-full store evicts pastes past
    // half their retention instead (see quota_pressure_evicts_old_pastes
    // below).
    let sv = serve(|c| {
        c.max_paste_bytes = 400;
        c.quota_bytes = 500;
    })
    .await;
    let (st, _, _) = post(sv.port, &[1u8; 400], "");
    assert_eq!(st, 507);
}

#[tokio::test(flavor = "multi_thread")]
async fn quota_pressure_evicts_old_pastes_but_never_fresh_ones() {
    let sv = serve(|c| {
        c.max_paste_bytes = 400;
        c.quota_bytes = 1100; // fits two 400-byte pastes (2 * 528), not three
    })
    .await;
    let slug_of = |body: Vec<u8>| {
        String::from_utf8(body)
            .unwrap()
            .trim()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string()
    };
    // an old paste (created far past retention/2) is fair game for eviction
    sv.ctx
        .store
        .insert_paste("old00001", &[9u8; 400], "203.0.113.7", 100, far())
        .unwrap();
    let (st, _, body) = post(sv.port, &[1u8; 400], "");
    assert_eq!(st, 200);
    let fresh = slug_of(body);
    let (st, _, body) = post(sv.port, &[2u8; 400], "");
    assert_eq!(
        st, 200,
        "quota pressure with an old paste must evict, not refuse"
    );
    let newest = slug_of(body);
    let (st, _, _) = get(sv.port, "/raw/old00001");
    assert_eq!(st, 404, "the old paste must have been evicted");
    let (st, _, _) = get(sv.port, &format!("/raw/{fresh}"));
    assert_eq!(st, 200, "only the old paste should go");
    let (st, _, raw) = get(sv.port, &format!("/raw/{newest}"));
    assert_eq!(st, 200);
    assert_eq!(raw, vec![2u8; 400]);
    assert!(
        sv.ctx.store.total_size() <= 1100,
        "eviction must keep the total under quota"
    );
    // nothing old remains: the next overflow paste is refused, and the
    // fresh pastes it would have destroyed survive
    let (st, _, _) = post(sv.port, &[3u8; 400], "");
    assert_eq!(
        st, 507,
        "with only fresh pastes stored, refuse instead of evicting"
    );
    let (st, _, _) = get(sv.port, &format!("/raw/{fresh}"));
    assert_eq!(st, 200, "fresh pastes must never be evicted");
    let (st, _, _) = get(sv.port, &format!("/raw/{newest}"));
    assert_eq!(st, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn conn_permit_gates_http_when_exhausted() {
    let sv = serve(|c| c.max_conns = 1).await;
    let _p = sv.ctx.conn_sem.clone().try_acquire_owned().unwrap();
    let (st, h, _) = get(sv.port, "/");
    assert_eq!(st, 503);
    assert_eq!(h["x-content-type-options"], "nosniff");
    drop(_p);
    let (st, _, _) = get(sv.port, "/");
    assert_eq!(st, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn banned_and_rate_limited_clients_beat_the_size_check() {
    // Ban/rate policy runs before the body is collected, so an oversized
    // body from a banned or rate-limited client must not shadow the policy
    // rejection behind a 413.
    let banned = serve(|c| c.max_paste_bytes = 100).await;
    banned
        .ctx
        .bans
        .replace(vec![("203.0.113.0/24".parse().unwrap(), None)]);
    let (st, _, _) = post(banned.port, &[7u8; 200], "X-Forwarded-For: 203.0.113.9\r\n");
    assert_eq!(st, 403, "banned + oversized body must be 403, not 413");

    let limited = serve(|c| {
        c.max_paste_bytes = 100;
        c.rate_burst = 1.0;
        c.rate_per_minute = 0.6;
    })
    .await;
    let (st, _, _) = post(limited.port, b"a", ""); // consumes the single burst token
    assert_eq!(st, 200);
    let (st, _, _) = post(limited.port, &[7u8; 200], "");
    assert_eq!(
        st, 429,
        "rate limited + oversized body must be 429, not 413"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn landing_page_substitutes_base_url() {
    let sv = serve(|_| {}).await;
    let (st, _, body) = get(sv.port, "/");
    assert_eq!(st, 200);
    let body = String::from_utf8(body).unwrap();
    assert!(body.contains("https://t.local"), "{body:?}");
    // Check that the page displays this instance's configured values.
    assert!(body.contains("512 KiB"), "max_paste_bytes: {body:?}");
    assert!(body.contains("30 days"), "retention_days: {body:?}");
    assert!(body.contains("encryption off"), "encrypt_at_rest: {body:?}");
    // Shell examples contain braces; match the full template placeholder shape.
    assert_eq!(
        unsubstituted(&body),
        Vec::<String>::new(),
        "unsubstituted placeholders"
    );
}

/// Any remaining `{lower_snake}` run, which is what a missed `.replace` in
/// `landing` leaves behind.
fn unsubstituted(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b = body.as_bytes();
    for (i, _) in body.match_indices('{') {
        let rest = &b[i + 1..];
        let len = rest
            .iter()
            .position(|c| !(c.is_ascii_lowercase() || *c == b'_'))
            .unwrap_or(0);
        if len > 0 && rest.get(len) == Some(&b'}') {
            out.push(body[i..=i + len + 1].to_string());
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn landing_page_states_the_configured_contact_without_the_address() {
    let sv = serve(|c| c.contact_email = Some("abuse@example.org".into())).await;
    let (st, _, body) = get(sv.port, "/");
    assert_eq!(st, 200);
    let body = String::from_utf8(body).unwrap();
    // Split across two attributes, so the page never carries the address as
    // one harvestable string.
    assert!(body.contains(r#"data-u="abuse""#), "{body:?}");
    assert!(body.contains(r#"data-d="example.org""#), "{body:?}");
    assert!(
        !body.contains("abuse@example.org"),
        "address appears verbatim: {body:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn landing_page_leaves_the_contact_empty_when_unset() {
    let sv = serve(|_| {}).await;
    let (_, _, body) = get(sv.port, "/");
    let body = String::from_utf8(body).unwrap();
    assert!(body.contains(r#"data-u="""#), "{body:?}");
    assert!(body.contains(r#"data-d="""#), "{body:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn rate_refusals_past_threshold_earn_an_immediate_ban() {
    let sv = serve(|c| {
        c.rate_burst = 1.0;
        c.rate_per_minute = 0.6;
        c.autoban_threshold = 3;
        c.autoban_window_secs = 60;
        c.autoban_minutes = 30;
    })
    .await;
    let xff = "X-Forwarded-For: 203.0.113.42\r\n";
    // The first post consumes the burst token. Posts 2..4 receive 429;
    // the third refusal triggers the ban, so post 5 receives 403.
    let (st, _, _) = post(sv.port, b"1", xff);
    assert_eq!(st, 200);
    let (st, _, _) = post(sv.port, b"2", xff);
    assert_eq!(st, 429);
    let (st, _, _) = post(sv.port, b"3", xff);
    assert_eq!(st, 429);
    let (st, _, _) = post(sv.port, b"4", xff);
    assert_eq!(st, 429);
    let (st, _, _) = post(sv.port, b"5", xff);
    assert_eq!(st, 403, "3rd refusal must have tripped an immediate ban");

    // a different source is unaffected
    let (st, _, _) = post(sv.port, b"x", "X-Forwarded-For: 198.51.100.9\r\n");
    assert_eq!(st, 200);

    let rows = sv.ctx.store.ban_rows().unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].0.starts_with("203.0.113.42"));
    assert!(rows[0].1.as_deref().unwrap_or("").contains("auto"));
}

#[tokio::test(flavor = "multi_thread")]
async fn source_cap_refuses_the_extra_paste_with_429() {
    let sv = serve(|c| c.max_pastes_per_source = 2).await;
    let (st, _, _) = post(sv.port, b"a", "");
    assert_eq!(st, 200);
    let (st, _, _) = post(sv.port, b"b", "");
    assert_eq!(st, 200);
    let (st, _, body) = post(sv.port, b"c", "");
    assert_eq!(st, 429);
    assert_eq!(
        String::from_utf8_lossy(&body),
        "scrip: paste limit reached for your network\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn source_cap_aggregates_across_a_48() {
    // max_pastes_per_source 1 gives the covering /48 a budget of 8: eight
    // distinct /64s in one /48 fill it, and the ninth is refused even though
    // its own /64 holds nothing.
    let sv = serve(|c| c.max_pastes_per_source = 1).await;
    for i in 0..8 {
        let (st, _, _) = post(
            sv.port,
            b"a",
            &format!("X-Forwarded-For: 2001:db8:1:{i:x}::7\r\n"),
        );
        assert_eq!(st, 200, "/64 number {i} should fit");
    }
    let (st, _, body) = post(sv.port, b"a", "X-Forwarded-For: 2001:db8:1:8::7\r\n");
    assert_eq!(st, 429);
    assert_eq!(
        String::from_utf8_lossy(&body),
        "scrip: paste limit reached for your network\n"
    );
    // a different /48 is unaffected
    let (st, _, _) = post(sv.port, b"a", "X-Forwarded-For: 2001:db8:2::7\r\n");
    assert_eq!(st, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn banned_ip_cannot_read_view_or_raw() {
    let sv = serve(|_| {}).await;
    let (_, _, body) = post(sv.port, b"secret", "");
    let slug = String::from_utf8(body)
        .unwrap()
        .trim()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    sv.ctx
        .bans
        .replace(vec![("203.0.113.0/24".parse().unwrap(), None)]);
    let banned_get = |path: &str| {
        request(
            sv.port,
            &format!(
                "GET {path} HTTP/1.0\r\nHost: t.local\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n"
            ),
            b"",
        )
    };
    let (st, _, _) = banned_get(&format!("/{slug}"));
    assert_eq!(st, 403, "banned source must not read the view page");
    let (st, _, _) = banned_get(&format!("/raw/{slug}"));
    assert_eq!(st, 403, "banned source must not read raw");
    // /healthz stays ungated so monitoring keeps working from anywhere
    let (st, _, _) = banned_get("/healthz");
    assert_eq!(st, 200);
    // Bans also block static assets, preventing repeated downloads of the bundle.
    let (st, _, _) = banned_get("/assets/hl.js");
    assert_eq!(st, 403, "banned source must not pull assets either");
    // an unbanned client still gets them
    let (st, _, _) = get(sv.port, "/assets/hl.js");
    assert_eq!(st, 200);
    // an unbanned client still reads
    let (st, _, _) = get(sv.port, &format!("/raw/{slug}"));
    assert_eq!(st, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn read_burst_exhaustion_is_429_and_feeds_the_autoban() {
    let sv = serve(|c| {
        c.read_burst = 1.0;
        c.read_rate_per_min = 0.6;
        c.autoban_threshold = 1;
        c.autoban_window_secs = 60;
        c.autoban_minutes = 30;
    })
    .await;
    let probe = |path: &str| {
        request(
            sv.port,
            &format!(
                "GET {path} HTTP/1.0\r\nHost: t.local\r\nX-Forwarded-For: 203.0.113.77\r\n\r\n"
            ),
            b"",
        )
    };
    let (st, _, _) = probe("/raw/zzzzzzzz");
    assert_eq!(st, 404); // consumes the single read token
    let (st, _, _) = probe("/zzzzzzzz");
    assert_eq!(st, 429, "view shares the read tier: burst exhausted");
    // the refusal fed note_rate_refusal: with threshold 1 the ban lands
    // before the 429 is even returned
    let (st, _, _) = probe("/raw/zzzzzzzz");
    assert_eq!(st, 403, "sustained probing must trip the auto-ban");
    let rows = sv.ctx.store.ban_rows().unwrap();
    assert_eq!(
        rows.len(),
        1,
        "read refusals must feed the auto-ban tracker"
    );
    assert!(rows[0].0.starts_with("203.0.113.77"));
    assert!(rows[0].1.as_deref().unwrap_or("").contains("auto"));
    // another source still reads freely
    let (st, _, _) = request(
        sv.port,
        "GET /zzzzzzzz HTTP/1.0\r\nHost: t.local\r\nX-Forwarded-For: 198.51.100.9\r\n\r\n",
        b"",
    );
    assert_eq!(st, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn app_assets_and_html_are_not_immutably_cached() {
    // Vendored pinned files cache forever; first-party app assets and HTML
    // must revalidate, or returning browsers keep stale code across releases.
    let sv = serve(|_| {}).await;
    for path in ["/assets/view.js", "/assets/view.css"] {
        let (st, h, _) = get(sv.port, path);
        assert_eq!(st, 200, "{path}");
        assert_eq!(h["cache-control"], "no-cache", "{path}");
    }
    let (_, h, _) = get(sv.port, "/");
    assert_eq!(h["cache-control"], "no-cache", "html must revalidate");
    // vendored stays immutable
    let (_, h, _) = get(sv.port, "/assets/hl.js");
    assert_eq!(h["cache-control"], "public, max-age=31536000, immutable");
}

fn post_path(
    port: u16,
    path: &str,
    body: &[u8],
) -> (u16, std::collections::HashMap<String, String>, Vec<u8>) {
    request(
        port,
        &format!(
            "POST {path} HTTP/1.0\r\nHost: t.local\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ),
        body,
    )
}

fn delete_req(
    port: u16,
    slug: &str,
    token: Option<&str>,
) -> (u16, std::collections::HashMap<String, String>, Vec<u8>) {
    let hdr = token
        .map(|t| format!("X-Delete-Token: {t}\r\n"))
        .unwrap_or_default();
    request(
        port,
        &format!("DELETE /{slug} HTTP/1.0\r\nHost: t.local\r\n{hdr}\r\n"),
        b"",
    )
}

fn slug_of(body: &[u8]) -> String {
    String::from_utf8(body.to_vec())
        .unwrap()
        .trim()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string()
}

fn expiry_span(sv: &support::TestServer, slug: &str) -> i64 {
    let conn = rusqlite::Connection::open(&sv.ctx.config.db_path).unwrap();
    let (created, expires): (i64, i64) = conn
        .query_row(
            "SELECT created_at, expires_at FROM paste WHERE slug = ?1",
            [slug],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    expires - created
}

#[tokio::test(flavor = "multi_thread")]
async fn ttl_param_sets_expiry_and_clamps_to_retention() {
    let sv = serve(|_| {}).await;
    let retention = sv.ctx.config.retention_days as i64 * 86_400;

    // no ttl: the configured retention
    let (st, _, body) = post(sv.port, b"x", "");
    assert_eq!(st, 200);
    assert_eq!(expiry_span(&sv, &slug_of(&body)), retention);

    let (st, _, body) = post_path(sv.port, "/?ttl=120", b"x");
    assert_eq!(st, 200);
    assert_eq!(expiry_span(&sv, &slug_of(&body)), 120);

    let (st, _, body) = post_path(sv.port, "/?ttl=2h", b"x");
    assert_eq!(st, 200);
    assert_eq!(expiry_span(&sv, &slug_of(&body)), 7_200);

    // over retention clamps down, under a minute clamps up
    let (st, _, body) = post_path(sv.port, "/?ttl=9999d", b"x");
    assert_eq!(st, 200);
    assert_eq!(expiry_span(&sv, &slug_of(&body)), retention);
    let (st, _, body) = post_path(sv.port, "/?ttl=1", b"x");
    assert_eq!(st, 200);
    assert_eq!(expiry_span(&sv, &slug_of(&body)), 60);
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_ttl_or_burn_values_are_400() {
    let sv = serve(|_| {}).await;
    for path in [
        "/?ttl=banana",
        "/?ttl=0",
        "/?ttl=-5m",
        "/?ttl=",
        "/?burn=maybe",
    ] {
        let (st, _, _) = post_path(sv.port, path, b"x");
        assert_eq!(st, 400, "{path}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn burn_paste_survives_viewing_and_dies_on_first_raw_read() {
    let sv = serve(|_| {}).await;
    let (st, h, body) = post_path(sv.port, "/?burn=1", b"secret");
    assert_eq!(st, 200);
    let slug = slug_of(&body);
    let tok = &h["x-delete-token"];
    assert_eq!(tok.len(), 32, "128-bit hex token");

    // the viewer warns instead of rendering, and does not consume
    for _ in 0..2 {
        let (st, _, page) = get(sv.port, &format!("/{slug}"));
        assert_eq!(st, 200);
        assert!(
            String::from_utf8_lossy(&page).contains("self-destructs"),
            "burn viewer must warn, not render"
        );
    }
    // first raw read returns the body, second finds nothing
    let (st, _, raw) = get(sv.port, &format!("/raw/{slug}"));
    assert_eq!(st, 200);
    assert_eq!(raw, b"secret");
    let (st, _, _) = get(sv.port, &format!("/raw/{slug}"));
    assert_eq!(st, 404);
    let (st, _, _) = get(sv.port, &format!("/{slug}"));
    assert_eq!(st, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_token_removes_the_paste() {
    let sv = serve(|_| {}).await;
    let (st, h, body) = post(sv.port, b"seekrit", "");
    assert_eq!(st, 200);
    let slug = slug_of(&body);
    let tok = h["x-delete-token"].clone();

    // wrong token: 404 and the paste stays
    let (st, _, _) = delete_req(sv.port, &slug, Some("00000000000000000000000000000000"));
    assert_eq!(st, 404);
    let (st, _, _) = get(sv.port, &format!("/raw/{slug}"));
    assert_eq!(st, 200);
    // no token header at all: 400
    let (st, _, _) = delete_req(sv.port, &slug, None);
    assert_eq!(st, 400);
    // right token: gone, and a second delete is a 404
    let (st, _, _) = delete_req(sv.port, &slug, Some(&tok));
    assert_eq!(st, 200);
    let (st, _, _) = get(sv.port, &format!("/raw/{slug}"));
    assert_eq!(st, 404);
    let (st, _, _) = delete_req(sv.port, &slug, Some(&tok));
    assert_eq!(st, 404);
}

fn head(port: u16, path: &str) -> (u16, std::collections::HashMap<String, String>, Vec<u8>) {
    request(
        port,
        &format!("HEAD {path} HTTP/1.0\r\nHost: t.local\r\n\r\n"),
        b"",
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn head_probe_never_consumes_a_burn_paste() {
    let sv = serve(|_| {}).await;
    let (_, _, body) = post_path(sv.port, "/?burn=1", b"secret");
    let slug = slug_of(&body);

    // a HEAD probe (curl -I, link checkers) answers 200 without claiming
    let (st, _, _) = head(sv.port, &format!("/raw/{slug}"));
    assert_eq!(st, 200);
    // the paste is still there for the real GET, exactly once
    let (st, _, raw) = get(sv.port, &format!("/raw/{slug}"));
    assert_eq!(st, 200);
    assert_eq!(raw, b"secret");
    let (st, _, _) = head(sv.port, &format!("/raw/{slug}"));
    assert_eq!(st, 404);

    // normal pastes answer HEAD too
    let (_, _, body) = post(sv.port, b"plain", "");
    let (st, _, _) = head(sv.port, &format!("/raw/{}", slug_of(&body)));
    assert_eq!(st, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn ban_outranks_a_malformed_query_string() {
    let sv = serve(|_| {}).await;
    sv.ctx.bans.insert("127.0.0.1/32".parse().unwrap(), None);
    // a duplicated ttl key rejects at the Query extractor; the ban check
    // must still come first, so this is a 403, not a 400
    let (st, _, _) = post_path(sv.port, "/?ttl=1m&ttl=2h", b"x");
    assert_eq!(st, 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_paste_roundtrips_and_the_db_holds_only_ciphertext() {
    let sv = serve(|c| c.encrypt_at_rest = true).await;
    let (st, h, body) = post(sv.port, b"secret contents", "");
    assert_eq!(st, 200);
    let token = slug_of(&body);
    assert_eq!(token.len(), 26, "URL carries the encryption token");
    assert!(h.contains_key("x-delete-token"));

    // the server decrypts on read, viewer and raw both work
    let (st, _, raw) = get(sv.port, &format!("/raw/{token}"));
    assert_eq!(st, 200);
    assert_eq!(raw, b"secret contents");
    let (st, _, _) = get(sv.port, &format!("/{token}"));
    assert_eq!(st, 200);

    // the database holds neither the token nor the plaintext
    let conn = rusqlite::Connection::open(&sv.ctx.config.db_path).unwrap();
    let (slug, blob): (String, Vec<u8>) = conn
        .query_row("SELECT slug, body FROM paste", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(slug.len(), 64, "row is keyed by the hashed id");
    assert_ne!(slug, token);
    assert!(
        !blob
            .windows(b"secret contents".len())
            .any(|w| w == b"secret contents"),
        "body must be ciphertext"
    );

    // the stored id is not addressable from a URL
    let (st, _, _) = get(sv.port, &format!("/raw/{slug}"));
    assert_eq!(st, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_burn_and_delete_work_end_to_end() {
    let sv = serve(|c| c.encrypt_at_rest = true).await;

    let (_, _, body) = post_path(sv.port, "/?burn=1", b"once");
    let token = slug_of(&body);
    let (st, _, page) = get(sv.port, &format!("/{token}"));
    assert_eq!(st, 200);
    assert!(String::from_utf8_lossy(&page).contains("self-destructs"));
    let (st, _, _) = head(sv.port, &format!("/raw/{token}"));
    assert_eq!(st, 200, "a HEAD probe must not consume");
    let (st, _, raw) = get(sv.port, &format!("/raw/{token}"));
    assert_eq!(st, 200);
    assert_eq!(raw, b"once");
    let (st, _, _) = get(sv.port, &format!("/raw/{token}"));
    assert_eq!(st, 404);

    let (_, h, body) = post(sv.port, b"gone soon", "");
    let token = slug_of(&body);
    let tok = h["x-delete-token"].clone();
    let (st, _, _) = delete_req(sv.port, &token, Some(&tok));
    assert_eq!(st, 200);
    let (st, _, _) = get(sv.port, &format!("/raw/{token}"));
    assert_eq!(st, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_pastes_stay_readable_when_encryption_turns_on() {
    let sv = serve(|c| c.encrypt_at_rest = true).await;
    // a row from before the switch, stored under a plain slug
    sv.ctx
        .store
        .insert_paste("plainold", b"legacy", "::1", 1, far())
        .unwrap();
    let (st, _, raw) = get(sv.port, "/raw/plainold");
    assert_eq!(st, 200);
    assert_eq!(raw, b"legacy");
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_pastes_survive_the_flag_being_turned_off() {
    // The read path keys off the URL shape, not the config, so a paste
    // written under encryption stays readable after the operator switches
    // encryption off, and new pastes then land in plaintext.
    let sv = serve(|c| c.encrypt_at_rest = false).await;
    let token = scrip::crypto::token();
    let id = scrip::crypto::token_id(&token);
    sv.ctx
        .store
        .insert_paste(
            &id,
            &scrip::crypto::seal(&token, b"from before"),
            "::1",
            1,
            far(),
        )
        .unwrap();

    let (st, _, raw) = get(sv.port, &format!("/raw/{token}"));
    assert_eq!(st, 200);
    assert_eq!(raw, b"from before");

    let (_, _, body) = post(sv.port, b"after", "");
    let slug = slug_of(&body);
    assert_eq!(slug.len(), 8, "new pastes are plain again");
    let (st, _, raw) = get(sv.port, &format!("/raw/{slug}"));
    assert_eq!(st, 200);
    assert_eq!(raw, b"after");
}

#[tokio::test(flavor = "multi_thread")]
async fn assets_are_ban_gated_but_never_rate_gated() {
    // Asset fetches check bans without spending read tokens, so loading the
    // viewer's subresources does not rate-limit readers behind a shared NAT.
    let sv = serve(|c| {
        c.read_burst = 1.0;
        c.read_rate_per_min = 0.6;
    })
    .await;

    // Far past a burst of one: every asset fetch still succeeds.
    for i in 0..10 {
        let (st, _, _) = get(sv.port, "/assets/view.css");
        assert_eq!(st, 200, "asset fetch {i} was rate limited");
    }
    // The one token is still there for a real read path.
    let (st, _, _) = get(sv.port, "/aaaa");
    assert_eq!(st, 404, "assets spent the read budget");
    let (st, _, _) = get(sv.port, "/aaaa");
    assert_eq!(st, 429, "the read limiter should be exhausted now");

    // Bans still block asset requests.
    sv.ctx.bans.insert("127.0.0.1/32".parse().unwrap(), None);
    let (st, _, _) = get(sv.port, "/assets/view.css");
    assert_eq!(st, 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_response_carries_no_referrer() {
    // Under encrypt_at_rest the URL path is the decryption key, so a
    // default referrer policy hands it to every host a paste links out to.
    let sv = serve(|_| {}).await;
    for path in ["/", "/assets/view.css", "/nosuchslug", "/raw/nosuchslug"] {
        let (_, headers, _) = get(sv.port, path);
        assert_eq!(
            headers.get("referrer-policy").map(String::as_str),
            Some("no-referrer"),
            "missing on {path}"
        );
        assert_eq!(
            headers.get("x-content-type-options").map(String::as_str),
            Some("nosniff"),
            "missing on {path}"
        );
    }

    // Responses generated by middleware need headers too. Hold the only
    // connection permit to force a 503 from the middleware.
    let busy = serve(|c| c.max_conns = 1).await;
    let mut held = std::net::TcpStream::connect(("127.0.0.1", busy.port)).unwrap();
    {
        use std::io::Write;
        held.write_all(b"POST / HTTP/1.0\r\nHost: t.local\r\nContent-Length: 1000\r\n\r\nx")
            .unwrap();
        held.flush().unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let (st, headers, _) = get(busy.port, "/");
    assert_eq!(st, 503, "expected the global permit to be held");
    assert_eq!(
        headers.get("referrer-policy").map(String::as_str),
        Some("no-referrer"),
        "missing on the 503 the middleware builds"
    );
    assert_eq!(
        headers.get("x-content-type-options").map(String::as_str),
        Some("nosniff"),
        "missing on the 503 the middleware builds"
    );
    drop(held);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_per_source_connection_cap_covers_the_http_door() {
    use std::io::Write;

    // The per-source cap must cover slow HTTP requests to prevent one source
    // from exhausting the shared TCP and HTTP semaphore.
    let sv = serve(|c| c.max_conns_per_source = 1).await;

    // Hold one request open: complete headers, then a Content-Length the
    // body never satisfies, so the handler is still inside the body read
    // with the permit in hand.
    let mut held = std::net::TcpStream::connect(("127.0.0.1", sv.port)).unwrap();
    held.write_all(
        b"POST / HTTP/1.0\r\nHost: t.local\r\nX-Forwarded-For: 203.0.113.9\r\n\
          Content-Length: 1000\r\n\r\nx",
    )
    .unwrap();
    held.flush().unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let as_client = |ip: &str| {
        request(
            sv.port,
            &format!("GET /aaaa HTTP/1.0\r\nHost: t.local\r\nX-Forwarded-For: {ip}\r\n\r\n"),
            b"",
        )
    };

    // Same source, over its cap of one.
    let (st, _, body) = as_client("203.0.113.9");
    assert_eq!(st, 503);
    assert!(
        String::from_utf8_lossy(&body).contains("too many connections"),
        "{body:?}"
    );

    // A different source is unaffected: the cap is per source, not global.
    let (st, _, _) = as_client("198.51.100.4");
    assert_eq!(st, 404);

    // And loopback is exempt. Without a forwarded header the client_ip of a
    // proxied request is the proxy itself, so capping it would cap the whole
    // site at one source's budget.
    for _ in 0..3 {
        let (st, _, _) = get(sv.port, "/aaaa");
        assert_eq!(st, 404, "loopback must not be capped");
    }

    drop(held);
}

#[tokio::test(flavor = "multi_thread")]
async fn mutable_assets_revalidate_by_etag() {
    let sv = serve(|_| {}).await;
    for path in ["/assets/view.js", "/assets/view.css", "/assets/landing.js"] {
        let (st, h, body) = get(sv.port, path);
        assert_eq!(st, 200, "{path}");
        assert_eq!(h.get("cache-control").map(String::as_str), Some("no-cache"));
        let etag = h.get("etag").unwrap_or_else(|| panic!("no etag on {path}"));
        assert!(!body.is_empty(), "{path}");

        // The same etag comes back as 304 with no body, so a redeploy is the
        // only thing that makes a reader download the file again.
        let (st, _, body) = support::request(
            sv.port,
            &format!("GET {path} HTTP/1.0\r\nHost: t.local\r\nIf-None-Match: {etag}\r\n\r\n"),
            b"",
        );
        assert_eq!(st, 304, "{path}");
        assert!(body.is_empty(), "304 carried a body: {path}");

        // A stale etag has to serve the new file, or the viewer runs an old
        // script against a new shell.
        let (st, _, body) = support::request(
            sv.port,
            &format!(
                "GET {path} HTTP/1.0\r\nHost: t.local\r\nIf-None-Match: \"0000000000000000\"\r\n\r\n"
            ),
            b"",
        );
        assert_eq!(st, 200, "{path}");
        assert!(!body.is_empty(), "{path}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn vendored_assets_stay_immutable() {
    let sv = serve(|_| {}).await;
    let (st, h, _) = get(sv.port, "/assets/hl.js");
    assert_eq!(st, 200);
    // Vendored and versioned with the binary: cached for a year, so it must
    // not pay for a revalidation round trip.
    assert_eq!(
        h.get("cache-control").map(String::as_str),
        Some("public, max-age=31536000, immutable")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_log_grammar_is_served_and_loaded() {
    let sv = serve(|_| {}).await;
    let (st, _, body) = get(sv.port, "/assets/log.js");
    assert_eq!(st, 200);
    let js = String::from_utf8(body).unwrap();
    assert!(js.contains(r#"registerLanguage("log""#), "{js:?}");
    // Autodetect has to stay off: the grammar matches a little of almost any
    // text and would win detection on ordinary pastes.
    assert!(js.contains("disableAutodetect: true"), "{js:?}");

    // The viewer must load the grammar script.
    let (_, _, body) = post(sv.port, b"hello", "");
    let slug = String::from_utf8(body)
        .unwrap()
        .trim()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    let (_, _, page) = get(sv.port, &format!("/{slug}"));
    let page = String::from_utf8(page).unwrap();
    assert!(page.contains("/assets/log.js"), "{page:?}");
}
