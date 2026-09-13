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
