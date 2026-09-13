use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use axum::Router;

use crate::config::LogPastes;
use crate::intake::{
    note_rate_refusal, now_epoch, store_paste, Ctx, PasteOpts, StoreOutcome, SOURCE_CAPPED_MSG,
};

/// Bounds header read time at the hyper level (installed in `serve()`).
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Bounds body read + handler time (enforced by `request_deadline`).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Bounds a peer that stops reading the response (permit is released at
/// response construction, and hyper has no write timeout of its own, so an
/// unread response would otherwise pin the task/fd/buffer forever).
/// Keep-alive connections die at the cap and clients reconnect.
pub const CONNECTION_MAX_LIFETIME: Duration = Duration::from_secs(120);

/// Lets e2e tests shorten the request deadline without a separate build.
fn request_timeout() -> Duration {
    std::env::var("SCRIP_TEST_REQUEST_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(REQUEST_TIMEOUT)
}

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'";

const LANDING: &str = include_str!("../assets/index.html");
const SHELL: &str = include_str!("../assets/view.html");
const BURN_PAGE: &str = include_str!("../assets/burn.html");
const NOT_FOUND_PAGE: &str = include_str!("../assets/404.html");
const VIEW_JS: &str = include_str!("../assets/view.js");
const LANDING_JS: &str = include_str!("../assets/landing.js");
const LANDING_CSS: &str = include_str!("../assets/landing.css");
const VIEW_CSS: &str = include_str!("../assets/view.css");
const HL_JS: &str = include_str!("../assets/highlight.min.js");
const NIX_JS: &str = include_str!("../assets/nix.min.js");
const LOG_JS: &str = include_str!("../assets/log.js");
const THEME_GITHUB_LIGHT: &str = include_str!("../assets/theme-github-light.css");
const THEME_GITHUB_DARK: &str = include_str!("../assets/theme-github-dark.css");
const THEME_SOLARIZED_LIGHT: &str = include_str!("../assets/theme-solarized-light.css");
const THEME_SOLARIZED_DARK: &str = include_str!("../assets/theme-solarized-dark.css");
const THEME_NORD: &str = include_str!("../assets/theme-nord.css");
const THEME_CATPPUCCIN_LATTE: &str = include_str!("../assets/theme-catppuccin-latte.css");
const THEME_CATPPUCCIN_MOCHA: &str = include_str!("../assets/theme-catppuccin-mocha.css");

pub fn router(ctx: Arc<Ctx>) -> Router {
    let max = ctx.config.max_paste_bytes as usize;
    Router::new()
        .route("/", get(landing).post(create))
        .route("/healthz", get(|| async { "" }))
        .route("/assets/{file}", get(asset))
        .route("/raw/{slug}", get(raw))
        .route("/{slug}", get(view).delete(delete_paste))
        .layer(DefaultBodyLimit::max(max))
        .layer(middleware::from_fn(request_deadline))
        .layer(middleware::from_fn_with_state(ctx.clone(), conn_permit))
        // Apply headers outside the other middleware so its 503 and 504
        // responses receive them too.
        .layer(middleware::from_fn(security_headers))
        .with_state(ctx)
}

/// axum::serve builds hyper with no Timer, which silently disables
/// header_read_timeout. This loop installs one.
///
/// HTTP/1.1 only. hyper-util's `auto` builder sniffs for an h2c preface even
/// under `http1_only()` ("Does not do anything if used with
/// serve_connection_with_upgrades", still true in 0.1.20), and hyper's H2
/// path has no header_read_timeout of its own. Built off `http1::Builder`
/// instead, a preface is just a bad request line.
pub fn serve(
    listener: tokio::net::TcpListener,
    ctx: Arc<Ctx>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let app = router(ctx);
    tokio::spawn(async move {
        let mut set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        loop {
            // Reap finished connection tasks each iteration so the set
            // doesn't grow unboundedly on a long-lived server.
            while set.try_join_next().is_some() {}
            tokio::select! {
                _ = shutdown.changed() => break,
                r = listener.accept() => {
                    let Ok((stream, peer)) = r else {
                        tracing::error!("http accept: {}", r.unwrap_err());
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    };
                    let app = app.clone();
                    let mut rx = shutdown.clone();
                    set.spawn(async move {
                        let service = hyper_util::service::TowerToHyperService::new(app);
                        // ConnectInfo comes from the make-service in axum::serve;
                        // here the request extension is installed by hand.
                        let service = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                            req.extensions_mut()
                                .insert(ConnectInfo(peer));
                            let svc = service.clone();
                            async move { hyper::service::Service::call(&svc, req).await }
                        });
                        let mut builder = hyper::server::conn::http1::Builder::new();
                        builder
                            .timer(hyper_util::rt::TokioTimer::new())
                            .header_read_timeout(HEADER_READ_TIMEOUT);
                        let conn = builder
                            .serve_connection(hyper_util::rt::TokioIo::new(stream), service);
                        tokio::pin!(conn);
                        tokio::select! {
                            _ = conn.as_mut() => {}
                            _ = rx.changed() => {
                                conn.as_mut().graceful_shutdown();
                                let _ = conn.as_mut().await;
                            }
                            _ = tokio::time::sleep(CONNECTION_MAX_LIFETIME) => {
                                conn.as_mut().graceful_shutdown();
                                let _ = conn.as_mut().await;
                            }
                        }
                    });
                }
            }
        }
        // 10s cap: after graceful_shutdown a peer that stops reading would
        // stall the join forever.
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            while set.join_next().await.is_some() {}
        })
        .await;
    })
}

/// Adds nosniff and no-referrer to every response. Encrypted paste URLs
/// contain key material, so they must not be sent in Referer headers.
async fn security_headers(req: axum::extract::Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    h.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    res
}

/// Bounds body read + handler. Slow-header attacks are cut earlier by the
/// hyper-level header_read_timeout in serve().
async fn request_deadline(req: axum::extract::Request, next: Next) -> Response {
    match tokio::time::timeout(request_timeout(), next.run(req)).await {
        Ok(res) => res,
        Err(_) => text(StatusCode::GATEWAY_TIMEOUT, "request timed out\n".into()),
    }
}

/// The global connection semaphore bounds both listeners. Outermost
/// layer so the permit spans the whole request, including the body read.
///
/// Enforces the shared per-source cap so slow HTTP requests from one source
/// cannot exhaust the pool for TCP uploads. Uses `client_ip` to distinguish
/// clients behind the loopback proxy. A source that still resolves to loopback
/// is exempt; otherwise a missing X-Forwarded-For would cap the entire site
/// at one source's allowance.
async fn conn_permit(
    State(ctx): State<Arc<Ctx>>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let busy = |msg: &str| text(StatusCode::SERVICE_UNAVAILABLE, msg.into());
    let Ok(_permit) = ctx.conn_sem.clone().try_acquire_owned() else {
        return busy("server busy\n");
    };
    let _source = match req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| client_ip(ci.0.ip(), req.headers()))
    {
        Some(ip) if !ip.is_loopback() => match crate::intake::try_source(&ctx, ip) {
            Some(guard) => Some(guard),
            None => return busy("too many connections from your network\n"),
        },
        _ => None,
    };
    next.run(req).await
}

fn html(status: StatusCode, body: impl Into<Body>) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONTENT_SECURITY_POLICY, CSP)
        // frame-ancestors again, for anything old enough to ignore CSP
        .header(header::X_FRAME_OPTIONS, "DENY")
        .body(body.into())
        .unwrap()
}

/// Host part of base_url, for the `nc <host> 9999` line on the landing page.
fn base_host(base_url: &str) -> &str {
    let authority = base_url
        .split_once("://")
        .map_or(base_url, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or(base_url);
    // A bracketed IPv6 literal is full of colons; only a port can follow the ].
    if let Some(end) = authority.find(']') {
        return &authority[..=end];
    }
    authority.rsplit_once(':').map_or(authority, |(h, _)| h)
}

fn text(status: StatusCode, body: String) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body))
        .unwrap()
}

/// Vendored, version-pinned files: safe to cache forever.
fn asset_response(mime: &'static str, body: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .body(Body::from(body))
        .unwrap()
}

/// Content hash for cache validation. App assets keep their URLs across
/// releases, so browsers need a validator that changes with the file.
fn etag_for(body: &'static str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    body.hash(&mut h);
    format!("\"{:016x}\"", h.finish())
}

/// Requires revalidation for app assets and supplies an ETag. This keeps
/// view.js and view.html in sync across releases without downloading
/// unchanged files again.
fn mutable_asset_response(mime: &'static str, body: &'static str, headers: &HeaderMap) -> Response {
    let etag = etag_for(body);
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag))
    {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(header::CACHE_CONTROL, "no-cache")
            .header(header::ETAG, &etag)
            .body(Body::empty())
            .unwrap();
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::ETAG, &etag)
        .body(Body::from(body))
        .unwrap()
}

pub fn valid_slug(s: &str) -> bool {
    // Legacy plain slugs up to 16 chars, or exactly an encryption token.
    // The stored 64-hex id of an encrypted row is longer than both, so
    // ciphertext can never be addressed by id from a URL.
    ((1..=16).contains(&s.len()) || s.len() == crate::crypto::TOKEN_LEN)
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// What the database knows this URL path segment as: a token-length
/// segment is an encryption token, keyed by its hash; everything else is
/// the slug itself.
fn db_slug(slug: &str) -> String {
    if slug.len() == crate::crypto::TOKEN_LEN {
        crate::crypto::token_id(slug)
    } else {
        slug.to_string()
    }
}

/// For a token-length slug the fetched body is sealed and must be opened
/// with the URL token before it leaves the server. None means tampering or
/// corruption, never a wrong token (that hashes to a different id and
/// misses the lookup), so callers answer 500, not 404.
fn unsealed(slug: &str, body: Vec<u8>) -> Option<Vec<u8>> {
    if slug.len() != crate::crypto::TOKEN_LEN {
        return Some(body);
    }
    let plain = crate::crypto::open(slug, &body);
    if plain.is_none() {
        tracing::error!("a stored ciphertext failed to open: database corruption?");
    }
    plain
}

/// Trust X-Forwarded-For only from our own loopback proxy; the LAST header
/// line is the one our proxy appended (HAProxy/Traefik append a new line
/// rather than editing the client-supplied one), and within that line the
/// last comma-separated entry is the appended hop. `.get()` would read only
/// the first line, letting an attacker's own first line win. Everyone else
/// is who they say they are. Both the parsed value and the peer fallback are
/// canonicalized: an IPv4-mapped ::ffff:a.b.c.d must come out as its v4
/// address so v4 CIDR bans match it and it keys as itself, not as ::/64.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    let peer = peer.to_canonical();
    if !peer.is_loopback() {
        return peer;
    }
    headers
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .and_then(|v| v.trim().parse::<IpAddr>().ok())
        .map_or(peer, |ip| ip.to_canonical())
}

/// Bytes as KiB or MiB, whichever reads better at this size.
fn human_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    if n >= MIB && n % MIB == 0 {
        format!("{} MiB", n / MIB)
    } else if n >= MIB {
        format!("{:.1} MiB", n as f64 / MIB as f64)
    } else {
        format!("{} KiB", n.div_ceil(KIB))
    }
}

/// Trims a float for display: 6.0 reads as "6", 6.5 stays "6.5".
fn human_rate(n: f64) -> String {
    if (n - n.round()).abs() < f64::EPSILON {
        format!("{}", n.round() as i64)
    } else {
        format!("{n}")
    }
}

async fn landing(State(ctx): State<Arc<Ctx>>) -> Response {
    let c = &ctx.config;
    // The address is split here and joined by the client, so the page never
    // carries it as one harvestable string. An unset contact leaves both
    // halves empty and landing.js drops the control.
    let (user, domain) = c
        .contact_email
        .as_deref()
        .and_then(|a| a.split_once('@'))
        .unwrap_or(("", ""));
    html(
        StatusCode::OK,
        LANDING
            .replace("{base_url}", &c.base_url)
            .replace("{host}", base_host(&c.base_url))
            .replace("{max_paste_size}", &human_bytes(c.max_paste_bytes))
            .replace("{retention_days}", &c.retention_days.to_string())
            .replace("{rate_per_minute}", &human_rate(c.rate_per_minute))
            .replace(
                "{max_conns_per_source}",
                &c.max_conns_per_source.to_string(),
            )
            .replace(
                "{encrypt_at_rest}",
                if c.encrypt_at_rest { "on" } else { "off" },
            )
            .replace(
                "{enc_tone}",
                if c.encrypt_at_rest { "good" } else { "warn" },
            )
            .replace(
                "{log_tone}",
                match c.log_mode() {
                    crate::config::LogPastes::Off => "good",
                    _ => "warn",
                },
            )
            .replace(
                "{log_pastes}",
                match c.log_mode() {
                    crate::config::LogPastes::Off => "off",
                    crate::config::LogPastes::Url => "url only",
                    crate::config::LogPastes::Full => "full",
                },
            )
            .replace("{contact_user}", user)
            .replace("{contact_domain}", domain),
    )
}

/// Checks bans on static assets, including the 124 KB highlight.js bundle.
/// Asset requests do not spend read tokens: a viewer can fetch up to seven,
/// which would quickly exhaust the allowance for readers behind one NAT.
async fn asset(Path(file): Path<String>, headers: HeaderMap, _gate: BanGate) -> Response {
    match file.as_str() {
        "hl.js" => asset_response("application/javascript; charset=utf-8", HL_JS),
        "view.js" => {
            mutable_asset_response("application/javascript; charset=utf-8", VIEW_JS, &headers)
        }
        "view.css" => mutable_asset_response("text/css; charset=utf-8", VIEW_CSS, &headers),
        "landing.js" => mutable_asset_response(
            "application/javascript; charset=utf-8",
            LANDING_JS,
            &headers,
        ),
        "landing.css" => mutable_asset_response("text/css; charset=utf-8", LANDING_CSS, &headers),
        "nix.js" => asset_response("application/javascript; charset=utf-8", NIX_JS),
        "log.js" => {
            mutable_asset_response("application/javascript; charset=utf-8", LOG_JS, &headers)
        }
        "theme-github-light.css" => asset_response("text/css; charset=utf-8", THEME_GITHUB_LIGHT),
        "theme-github-dark.css" => asset_response("text/css; charset=utf-8", THEME_GITHUB_DARK),
        "theme-solarized-light.css" => {
            asset_response("text/css; charset=utf-8", THEME_SOLARIZED_LIGHT)
        }
        "theme-solarized-dark.css" => {
            asset_response("text/css; charset=utf-8", THEME_SOLARIZED_DARK)
        }
        "theme-nord.css" => asset_response("text/css; charset=utf-8", THEME_NORD),
        "theme-catppuccin-latte.css" => {
            asset_response("text/css; charset=utf-8", THEME_CATPPUCCIN_LATTE)
        }
        "theme-catppuccin-mocha.css" => {
            asset_response("text/css; charset=utf-8", THEME_CATPPUCCIN_MOCHA)
        }
        _ => text(StatusCode::NOT_FOUND, "not found\n".into()),
    }
}

async fn view(State(ctx): State<Arc<Ctx>>, Path(slug): Path<String>, _gate: ReadGate) -> Response {
    if !valid_slug(&slug) {
        return html(StatusCode::NOT_FOUND, NOT_FOUND_PAGE);
    }
    let st = ctx.store.clone();
    let s = db_slug(&slug);
    match tokio::task::spawn_blocking(move || st.burn_status(&s)).await {
        // The shell auto-fetches /raw to render, which would consume a burn
        // paste just by opening the page (or by a chat link preview). Burn
        // rows get a warning page with an explicit link instead.
        Ok(Ok(Some(true))) => html(
            StatusCode::OK,
            BURN_PAGE
                .replace("{base_url}", &ctx.config.base_url)
                .replace("{slug}", &slug),
        ),
        Ok(Ok(Some(false))) => html(StatusCode::OK, SHELL),
        Ok(Ok(None)) => html(StatusCode::NOT_FOUND, NOT_FOUND_PAGE),
        _ => text(StatusCode::INTERNAL_SERVER_ERROR, "internal error\n".into()),
    }
}

fn raw_response(body: Vec<u8>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .unwrap()
}

async fn raw(
    State(ctx): State<Arc<Ctx>>,
    Path(slug): Path<String>,
    method: axum::http::Method,
    _gate: ReadGate,
) -> Response {
    if !valid_slug(&slug) {
        return text(StatusCode::NOT_FOUND, "not found\n".into());
    }
    // axum's get() also answers HEAD, and hyper strips the body from a HEAD
    // response, so a HEAD probe (curl -I, link checkers) reaching the claim
    // below would destroy a burn paste with the content delivered to no one.
    // HEAD gets an existence answer instead, never the claim. Content-Length
    // is 0 rather than the body size; a probe that needs the size can GET.
    if method == axum::http::Method::HEAD {
        let st = ctx.store.clone();
        let id = db_slug(&slug);
        return match tokio::task::spawn_blocking(move || st.burn_status(&id)).await {
            Ok(Ok(Some(_))) => raw_response(Vec::new()),
            Ok(Ok(None)) => text(StatusCode::NOT_FOUND, "not found\n".into()),
            _ => text(StatusCode::INTERNAL_SERVER_ERROR, "internal error\n".into()),
        };
    }
    // Burn rows first: an atomic claim that only ever succeeds once. Normal
    // rows fall through to the plain read below.
    let st = ctx.store.clone();
    let id = db_slug(&slug);
    match tokio::task::spawn_blocking(move || st.claim_burn(&id)).await {
        Ok(Ok(Some(body))) => {
            return match unsealed(&slug, body) {
                Some(plain) => raw_response(plain),
                None => text(StatusCode::INTERNAL_SERVER_ERROR, "internal error\n".into()),
            }
        }
        Ok(Ok(None)) => {}
        _ => return text(StatusCode::INTERNAL_SERVER_ERROR, "internal error\n".into()),
    }
    let st = ctx.store.clone();
    let id = db_slug(&slug);
    match tokio::task::spawn_blocking(move || st.get_paste(&id)).await {
        Ok(Ok(Some(body))) => match unsealed(&slug, body) {
            Some(plain) => raw_response(plain),
            None => text(StatusCode::INTERNAL_SERVER_ERROR, "internal error\n".into()),
        },
        Ok(Ok(None)) => text(StatusCode::NOT_FOUND, "not found\n".into()),
        _ => text(StatusCode::INTERNAL_SERVER_ERROR, "internal error\n".into()),
    }
}

/// Runs ban and rate policy before the body is ever collected, so the order
/// (ban, rate, size) holds for oversized uploads too. `DefaultBodyLimit`
/// would otherwise 413 an oversized body before a banned or rate-limited
/// client's policy check ever ran.
struct PolicyGate;

/// Ban + rate policy for the read paths (view, raw, assets): a banned
/// source must not keep reading, and the 41-bit slug space must not be a
/// free unthrottled 200/404 oracle. Uses the generous read-tier limiter so
/// browsing never competes with paste creation for tokens. /healthz stays
/// ungated so monitoring works from anywhere.
struct ReadGate;

/// Ban policy for `/assets/*`; asset fetches do not spend read tokens.
struct BanGate;

/// Who the request is from, once the loopback-only X-Forwarded-For rule has
/// been applied. None means the ConnectInfo extension is missing, which is a
/// bug in `serve()`, not something a client can cause.
fn caller_ip(parts: &axum::http::request::Parts) -> Option<IpAddr> {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| client_ip(ci.0.ip(), &parts.headers))
}

/// Ban check alone, for the static assets: a banned source must not keep
/// pulling them, but an asset fetch must not spend a rate token (see
/// `asset`). `Some` is the rejection to send; `None` means carry on.
fn run_ban_gate(parts: &axum::http::request::Parts, ctx: &Arc<Ctx>) -> Option<Response> {
    let Some(ip) = caller_ip(parts) else {
        return Some(text(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error\n".into(),
        ));
    };
    ctx.bans
        .is_banned(ip, now_epoch())
        .then(|| text(StatusCode::FORBIDDEN, "forbidden\n".into()))
}

/// Shared ban + rate check for both gates; `limiter` picks the tier.
/// Refusals feed the same auto-ban tracker either way, so sustained probing
/// escalates into a real ban. Same convention as `run_ban_gate`: `Some` is
/// the rejection to send, `None` means carry on.
async fn run_gate(
    parts: &mut axum::http::request::Parts,
    ctx: &Arc<Ctx>,
    limiter: &crate::policy::RateLimiter,
) -> Option<Response> {
    if let Some(rejection) = run_ban_gate(parts, ctx) {
        return Some(rejection);
    }
    let Some(ip) = caller_ip(parts) else {
        return Some(text(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error\n".into(),
        ));
    };
    let admit = limiter.try_acquire(ip, std::time::Instant::now());
    if admit.refused() {
        note_rate_refusal(ctx, ip, admit).await;
        return Some(text(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limited, try again later\n".into(),
        ));
    }
    None
}

impl axum::extract::FromRequestParts<Arc<Ctx>> for PolicyGate {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        ctx: &Arc<Ctx>,
    ) -> Result<Self, Self::Rejection> {
        match run_gate(parts, ctx, &ctx.limiter).await {
            Some(rejection) => Err(rejection),
            None => Ok(PolicyGate),
        }
    }
}

impl axum::extract::FromRequestParts<Arc<Ctx>> for ReadGate {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        ctx: &Arc<Ctx>,
    ) -> Result<Self, Self::Rejection> {
        match run_gate(parts, ctx, &ctx.read_limiter).await {
            Some(rejection) => Err(rejection),
            None => Ok(ReadGate),
        }
    }
}

impl axum::extract::FromRequestParts<Arc<Ctx>> for BanGate {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        ctx: &Arc<Ctx>,
    ) -> Result<Self, Self::Rejection> {
        match run_ban_gate(parts, ctx) {
            Some(rejection) => Err(rejection),
            None => Ok(BanGate),
        }
    }
}

/// "90" = seconds; s/m/h/d suffixes scale. None on anything else, and the
/// caller answers 400: a typo must not silently become the default TTL.
fn parse_ttl(s: &str) -> Option<i64> {
    // A bare number is seconds; everything else is the CLI's own grammar,
    // rather than a second copy of it that can drift.
    s.parse::<i64>()
        .ok()
        .filter(|n| *n > 0)
        .or_else(|| crate::cli_util::parse_duration_secs(s).ok())
}

/// Per-paste options on the HTTP door. Unknown query keys are ignored, so
/// keys meant for other routes (?lang) cannot break a paste; known keys
/// with bad values are 400s.
#[derive(serde::Deserialize, Default)]
struct CreateParams {
    ttl: Option<String>,
    burn: Option<String>,
}

async fn create(
    State(ctx): State<Arc<Ctx>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    // The gate must run before Query: extractors run in declaration order,
    // and a query string that serde rejects (a duplicated ?ttl, say) would
    // otherwise answer 400 before the ban and rate checks ever ran.
    _gate: PolicyGate,
    Query(params): Query<CreateParams>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Ban + rate already ran in PolicyGate, before the body was collected.
    let ip = client_ip(peer.ip(), &headers);
    if body.is_empty() {
        return text(StatusCode::BAD_REQUEST, "empty paste\n".into());
    }
    let ttl_secs = match params.ttl.as_deref() {
        None => None,
        Some(v) => match parse_ttl(v) {
            Some(t) => Some(t),
            None => {
                return text(
                    StatusCode::BAD_REQUEST,
                    "bad ttl: use e.g. 90, 10m, 2h, 7d\n".into(),
                )
            }
        },
    };
    let burn = match params.burn.as_deref() {
        None | Some("0") | Some("false") => false,
        Some("") | Some("1") | Some("true") => true,
        Some(_) => {
            return text(
                StatusCode::BAD_REQUEST,
                "bad burn value: use burn=1\n".into(),
            )
        }
    };
    match store_paste(
        &ctx,
        ip,
        Arc::new(body.to_vec()),
        PasteOpts { ttl_secs, burn },
    )
    .await
    {
        StoreOutcome::Stored { slug, delete_token } => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header("x-delete-token", delete_token)
            .body(Body::from(format!("{}/{}\n", ctx.config.base_url, slug)))
            .unwrap(),
        StoreOutcome::QuotaFull => text(StatusCode::INSUFFICIENT_STORAGE, "storage full\n".into()),
        StoreOutcome::SourceCapped => text(StatusCode::TOO_MANY_REQUESTS, SOURCE_CAPPED_MSG.into()),
        StoreOutcome::Error => text(StatusCode::INTERNAL_SERVER_ERROR, "internal error\n".into()),
    }
}

/// DELETE /{slug} with the X-Delete-Token handed out at creation. One SQL
/// statement decides: a wrong token and a missing paste are the same 404,
/// which tells a prober nothing GET does not already tell them.
async fn delete_paste(
    State(ctx): State<Arc<Ctx>>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    _gate: PolicyGate,
) -> Response {
    if !valid_slug(&slug) {
        return text(StatusCode::NOT_FOUND, "not found\n".into());
    }
    let Some(token) = headers.get("x-delete-token").and_then(|v| v.to_str().ok()) else {
        return text(
            StatusCode::BAD_REQUEST,
            "missing X-Delete-Token header\n".into(),
        );
    };
    let hash = {
        use sha2::Digest;
        sha2::Sha256::digest(token.as_bytes()).to_vec()
    };
    let st = ctx.store.clone();
    let id = db_slug(&slug);
    let logged = id.clone();
    match tokio::task::spawn_blocking(move || st.delete_by_token(&id, &hash)).await {
        Ok(Ok(true)) => {
            // Same journald-retention rule as the stored line: off = no
            // slug. The logged name is the stored id, never the URL token,
            // for the same reason the stored line never logs the token.
            match ctx.config.log_mode() {
                LogPastes::Off => tracing::info!("deleted a paste via its token"),
                _ => tracing::info!("deleted paste {logged} via its token"),
            }
            text(StatusCode::OK, "deleted\n".into())
        }
        Ok(Ok(false)) => text(StatusCode::NOT_FOUND, "not found\n".into()),
        _ => text(StatusCode::INTERNAL_SERVER_ERROR, "internal error\n".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_gate() {
        assert!(valid_slug("a"));
        assert!(valid_slug("abcd1234"));
        assert!(valid_slug("aaaaaaaaaaaaaaaa")); // 16
        assert!(valid_slug(&"a".repeat(crate::crypto::TOKEN_LEN)));
        assert!(!valid_slug(&"a".repeat(17))); // between slug and token
        assert!(!valid_slug(&"a".repeat(crate::crypto::TOKEN_LEN + 1)));
        assert!(!valid_slug(&"a".repeat(64))); // a stored encrypted id
        assert!(!valid_slug(""));
        assert!(!valid_slug("aaaaaaaaaaaaaaaaa")); // 17
        assert!(!valid_slug("ABCD1234"));
        assert!(!valid_slug("../etc"));
        assert!(!valid_slug("a b"));
        assert!(!valid_slug("a\0b"));
        assert!(!valid_slug("a'or'1"));
    }

    proptest::proptest! {
        /// The same route-safety invariant `fuzz_slug_path` asserts, kept
        /// here too so that widening `valid_slug` fails the fast suite
        /// instead of only the nightly fuzz run.
        #[test]
        fn accepted_slugs_are_route_safe(s in "[a-z0-9]{0,80}") {
            // Drawn from the accepted alphabet on purpose: a generator of
            // arbitrary strings almost never produces one `valid_slug`
            // takes, so the body would pass without ever running.
            if valid_slug(&s) {
                assert!(!s.is_empty());
                assert!(s.len() <= 16 || s.len() == crate::crypto::TOKEN_LEN);
                assert!(!s.contains(['/', '.', '%', '\0']));
            }
        }
    }

    #[test]
    fn ttl_grammar() {
        assert_eq!(parse_ttl("90"), Some(90));
        assert_eq!(parse_ttl("90s"), Some(90));
        assert_eq!(parse_ttl("10m"), Some(600));
        assert_eq!(parse_ttl("2h"), Some(7_200));
        assert_eq!(parse_ttl("7d"), Some(604_800));
        assert_eq!(parse_ttl(""), None);
        assert_eq!(parse_ttl("m"), None);
        assert_eq!(parse_ttl("0"), None);
        assert_eq!(parse_ttl("-5m"), None);
        assert_eq!(parse_ttl("banana"), None);
        assert_eq!(parse_ttl("1e3"), None);
        assert_eq!(parse_ttl("9223372036854775807d"), None); // would overflow
    }

    #[test]
    fn base_host_strips_scheme_port_and_path() {
        assert_eq!(base_host("http://localhost:8080"), "localhost");
        assert_eq!(base_host("https://paste.example.com"), "paste.example.com");
        assert_eq!(
            base_host("https://paste.example.com:8443"),
            "paste.example.com"
        );
        assert_eq!(base_host("http://[::1]:8080"), "[::1]");
        assert_eq!(base_host("http://[::1]"), "[::1]");
    }

    #[test]
    fn forwarded_for_only_from_loopback() {
        let hm = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert("x-forwarded-for", v.parse().unwrap());
            h
        };
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let ext: IpAddr = "198.51.100.7".parse().unwrap();
        // loopback peer: last XFF entry wins
        assert_eq!(
            client_ip(lo, &hm("203.0.113.5")),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client_ip(lo, &hm("10.0.0.1, 203.0.113.5")),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
        // non-loopback peer: header ignored entirely
        assert_eq!(client_ip(ext, &hm("203.0.113.5")), ext);
        // garbage header: fall back to peer
        assert_eq!(client_ip(lo, &hm("not-an-ip")), lo);
        assert_eq!(client_ip(lo, &HeaderMap::new()), lo);
        // multiple XFF lines: the last is the proxy's, not the attacker's first
        let mut multi = HeaderMap::new();
        multi.append("x-forwarded-for", "203.0.113.5".parse().unwrap());
        multi.append("x-forwarded-for", "198.51.100.7".parse().unwrap());
        assert_eq!(
            client_ip(lo, &multi),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn mapped_v4_is_canonicalized_and_matches_v4_bans() {
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "::ffff:1.2.3.9".parse().unwrap());
        // proxy-forwarded mapped v4 canonicalizes to the plain v4 address
        assert_eq!(client_ip(lo, &h), "1.2.3.9".parse::<IpAddr>().unwrap());
        // so a v4 CIDR ban matches it through the client_ip path
        let bans = crate::policy::BanList::new();
        bans.insert("1.2.3.0/24".parse().unwrap(), None);
        assert!(bans.is_banned(client_ip(lo, &h), 0));
        // the peer fallback canonicalizes too
        let mapped_peer: IpAddr = "::ffff:198.51.100.7".parse().unwrap();
        assert_eq!(
            client_ip(mapped_peer, &HeaderMap::new()),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }
}
