/// "30d" / "12h" / "45m" / "90s" -> seconds
pub fn parse_duration_secs(s: &str) -> Result<i64, String> {
    let Some((idx, unit)) = s.char_indices().last() else {
        return Err(format!("bad duration: {s}"));
    };
    let n: i64 = s[..idx].parse().map_err(|_| format!("bad duration: {s}"))?;
    if n <= 0 {
        return Err(format!("bad duration: {s}"));
    }
    let mult = match unit {
        'd' => 86_400,
        'h' => 3_600,
        'm' => 60,
        's' => 1,
        _ => return Err(format!("bad duration unit in: {s} (use d/h/m/s)")),
    };
    n.checked_mul(mult)
        .ok_or_else(|| format!("duration too large: {s}"))
}

/// Bare IPv6 addresses become their /64, the unit auto-bans use.
pub fn ban_target(s: &str) -> Result<ipnet::IpNet, String> {
    if let Ok(net) = s.parse::<ipnet::IpNet>() {
        return Ok(net.trunc());
    }
    let ip: std::net::IpAddr = s
        .parse()
        .map_err(|_| format!("not an address or range: {s}"))?;
    let key = crate::policy::source_key(ip);
    let prefix = if key.is_ipv4() { 32 } else { 64 };
    Ok(ipnet::IpNet::new(key, prefix)
        .expect("32 and 64 are valid prefixes")
        .trunc())
}

pub fn paste_ref(s: &str) -> &str {
    let s = s.split(['?', '#']).next().unwrap_or(s);
    let s = s.trim_end_matches('/');
    s.rsplit('/').next().unwrap_or(s)
}

pub fn expiry(until: Option<i64>, now: i64) -> String {
    let Some(left) = until.map(|u| u - now) else {
        return "permanent".into();
    };
    match left {
        ..=0 => "expired".into(),
        1..=59 => format!("in {left}s"),
        60..=3_599 => format!("in {}m", left / 60),
        3_600..=86_399 => format!("in {}h", left / 3_600),
        _ => format!("in {}d", left / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ban_target_reads_a_bare_address_as_its_source() {
        let t = |s| ban_target(s).unwrap().to_string();
        assert_eq!(t("203.0.113.9"), "203.0.113.9/32");
        assert_eq!(t("2001:db8:1:2::77"), "2001:db8:1:2::/64");
        assert_eq!(t("::ffff:203.0.113.9"), "203.0.113.9/32");
        assert_eq!(t("10.0.102.0/24"), "10.0.102.0/24");
        assert_eq!(t("10.0.102.1/32"), "10.0.102.1/32");
        assert_eq!(t("203.0.113.9/24"), "203.0.113.0/24");
        assert!(ban_target("not-a-cidr").is_err());
    }

    #[test]
    fn paste_ref_takes_what_people_paste() {
        for s in [
            "abcd1234",
            "https://paste.example.com/abcd1234",
            "https://paste.example.com/raw/abcd1234",
            "paste.example.com/abcd1234?lang=rust#L3-L9",
            "/raw/abcd1234/",
        ] {
            assert_eq!(paste_ref(s), "abcd1234", "{s}");
        }
    }

    #[test]
    fn expiry_reads_like_a_duration() {
        let now = 1_000_000;
        assert_eq!(expiry(None, now), "permanent");
        assert_eq!(expiry(Some(now), now), "expired");
        assert_eq!(expiry(Some(now + 59), now), "in 59s");
        assert_eq!(expiry(Some(now + 27 * 60 + 30), now), "in 27m");
        assert_eq!(expiry(Some(now + 3 * 3600), now), "in 3h");
        assert_eq!(expiry(Some(now + 2 * 86_400 + 5), now), "in 2d");
    }
}
