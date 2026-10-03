use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/scrip/scrip.toml";

/// Detail logged for stored pastes: "full" includes the stored id, size and
/// author IP, "url" omits the IP, and "off" records only size. Logs can
/// outlive paste expiry and takedown. Defaults to "url", or "off" with
/// `encrypt_at_rest` to avoid linking stored ids to request metadata. An
/// explicit setting overrides the default; see `Config::log_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogPastes {
    Url,
    Full,
    Off,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub listen_tcp: Vec<SocketAddr>,
    pub listen_http: Vec<SocketAddr>,
    pub base_url: String,
    pub db_path: PathBuf,
    pub max_paste_bytes: u64,
    pub idle_timeout_secs: u64,
    pub total_deadline_secs: u64,
    pub retention_days: u64,
    pub quota_bytes: u64,
    pub rate_per_minute: f64,
    pub rate_burst: f64,
    pub read_rate_per_min: f64,
    pub read_burst: f64,
    pub max_conns: usize,
    pub max_conns_per_source: usize,
    pub ban_reload_secs: u64,
    pub gc_interval_secs: u64,
    pub autoban_threshold: u32,
    pub autoban_window_secs: u64,
    pub autoban_minutes: u64,
    pub autoban_factor: f64,
    pub autoban_max_minutes: u64,
    pub autoban_forget_days: u64,
    pub max_pastes_per_source: u32,
    /// None = not set in the file; `log_mode()` picks the real default.
    pub log_pastes: Option<LogPastes>,
    pub encrypt_at_rest: bool,
    /// Shown on the landing page for takedowns and abuse. Unset hides the
    /// contact line entirely rather than printing an empty link.
    pub contact_email: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen_tcp: vec![
                "[::]:9999".parse().unwrap(),
                "0.0.0.0:9999".parse().unwrap(),
            ],
            listen_http: vec!["127.0.0.1:8080".parse().unwrap()],
            base_url: "http://localhost:8080".into(),
            db_path: "scrip.db".into(),
            max_paste_bytes: 512 * 1024,
            idle_timeout_secs: 5,
            total_deadline_secs: 30,
            retention_days: 30,
            quota_bytes: 1024 * 1024 * 1024,
            rate_per_minute: 6.0,
            rate_burst: 5.0,
            read_rate_per_min: 120.0,
            read_burst: 60.0,
            max_conns: 1024,
            // Shared by TCP and HTTP. Allow room for a viewer page and its
            // subresources, including browsers with six connections per host.
            // Twelve also exceeds the kernel's ten-connection intake cap.
            max_conns_per_source: 12,
            ban_reload_secs: 10,
            gc_interval_secs: 3600,
            autoban_threshold: 20,
            autoban_window_secs: 60,
            autoban_minutes: 30,
            autoban_factor: 2.0,
            autoban_max_minutes: 1440,
            autoban_forget_days: 7,
            max_pastes_per_source: 100,
            log_pastes: None,
            encrypt_at_rest: false,
            contact_email: None,
        }
    }
}

impl Config {
    /// The effective log shape: an explicit `log_pastes` wins; otherwise
    /// "url", or "off" under encryption at rest.
    pub fn log_mode(&self) -> LogPastes {
        self.log_pastes.unwrap_or(if self.encrypt_at_rest {
            LogPastes::Off
        } else {
            LogPastes::Url
        })
    }

    /// Explicit path must exist. With no explicit path, the system config is
    /// used when present, else pure defaults.
    pub fn load(explicit: Option<&Path>) -> Result<Config, String> {
        let path = match explicit {
            Some(p) => Some(p.to_path_buf()),
            None => {
                let d = Path::new(DEFAULT_CONFIG_PATH);
                d.exists().then(|| d.to_path_buf())
            }
        };
        match path {
            None => Ok(Config::default()),
            Some(p) => {
                let text = std::fs::read_to_string(&p)
                    .map_err(|e| format!("read config {}: {e}", p.display()))?;
                toml::from_str(&text).map_err(|e| format!("parse config {}: {e}", p.display()))
            }
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.listen_tcp.is_empty() {
            return Err("listen_tcp must not be empty".into());
        }
        let scheme_len = if self.base_url.starts_with("http://") {
            Some(7)
        } else if self.base_url.starts_with("https://") {
            Some(8)
        } else {
            None
        };
        match scheme_len {
            None => return Err("base_url must start with http:// or https://".into()),
            Some(n) if self.base_url[n..].is_empty() || self.base_url[n..].starts_with('/') => {
                return Err("base_url must have a host after the scheme".into())
            }
            Some(_) if self.base_url.ends_with('/') => {
                return Err("base_url must not end with a trailing slash".into())
            }
            Some(_) if self.base_url.contains(['"', '<', '>']) => {
                return Err("base_url contains invalid characters".into())
            }
            Some(_) => {}
        }
        if self.max_paste_bytes == 0 {
            return Err("max_paste_bytes must be at least 1".into());
        }
        if self.quota_bytes < self.max_paste_bytes {
            return Err("quota_bytes must be at least max_paste_bytes".into());
        }
        if self.idle_timeout_secs == 0 || self.total_deadline_secs < self.idle_timeout_secs {
            return Err("total_deadline_secs must be >= idle_timeout_secs >= 1".into());
        }
        if self.rate_burst < 1.0 || self.rate_per_minute <= 0.0 {
            return Err("rate_burst must be >= 1 and rate_per_minute > 0".into());
        }
        if self.read_burst < 1.0 || self.read_rate_per_min <= 0.0 {
            return Err("read_burst must be >= 1 and read_rate_per_min > 0".into());
        }
        if self.max_conns == 0 || self.max_conns_per_source == 0 {
            return Err("connection caps must be >= 1".into());
        }
        if self.max_conns > 65536 {
            return Err("max_conns must be <= 65536".into());
        }
        if self.retention_days == 0 || self.retention_days > 36500 {
            return Err("retention_days must be between 1 and 36500".into());
        }
        if self.ban_reload_secs == 0 {
            return Err("ban_reload_secs must be >= 1".into());
        }
        if self.gc_interval_secs == 0 {
            return Err("gc_interval_secs must be >= 1".into());
        }
        if self.autoban_threshold == 0 {
            return Err("autoban_threshold must be >= 1".into());
        }
        if self.autoban_window_secs == 0 {
            return Err("autoban_window_secs must be >= 1".into());
        }
        if self.autoban_factor < 1.0 {
            return Err("autoban_factor must be >= 1.0".into());
        }
        if self.autoban_minutes > 0 && self.autoban_max_minutes < self.autoban_minutes {
            return Err("autoban_max_minutes must be >= autoban_minutes".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = Config::default();
        assert_eq!(c.base_url, "http://localhost:8080");
        assert_eq!(c.max_paste_bytes, 512 * 1024);
        assert_eq!(c.read_rate_per_min, 120.0);
        assert_eq!(c.read_burst, 60.0);
        assert_eq!(c.idle_timeout_secs, 5);
        assert_eq!(c.total_deadline_secs, 30);
        assert!(!c.listen_tcp.is_empty());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn no_path_and_no_system_file_yields_defaults() {
        // Explicit None + nonexistent default path = defaults. We cannot control
        // /etc in tests, so this asserts only that load(None) succeeds.
        assert!(Config::load(None).is_ok());
    }

    #[test]
    fn file_values_override_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("scrip.toml");
        std::fs::write(
            &p,
            "base_url = \"https://paste.example.com\"\nmax_paste_bytes = 1024\n",
        )
        .unwrap();
        let c = Config::load(Some(&p)).unwrap();
        assert_eq!(c.base_url, "https://paste.example.com");
        assert_eq!(c.max_paste_bytes, 1024);
        assert_eq!(c.idle_timeout_secs, 5); // untouched key keeps its default
    }

    #[test]
    fn explicit_missing_file_is_an_error() {
        assert!(Config::load(Some(std::path::Path::new("/nonexistent/scrip.toml"))).is_err());
    }

    #[test]
    fn unknown_key_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("scrip.toml");
        std::fs::write(&p, "no_such_key = 1\n").unwrap();
        assert!(Config::load(Some(&p)).is_err());
    }

    #[test]
    fn log_pastes_parses_all_three_and_defaults_to_url() {
        assert_eq!(Config::default().log_mode(), LogPastes::Url);
        for (text, want) in [
            ("log_pastes = \"url\"\n", LogPastes::Url),
            ("log_pastes = \"full\"\n", LogPastes::Full),
            ("log_pastes = \"off\"\n", LogPastes::Off),
        ] {
            let c: Config = toml::from_str(text).unwrap();
            assert_eq!(c.log_mode(), want, "{text}");
        }
        assert!(toml::from_str::<Config>("log_pastes = \"loud\"\n").is_err());
    }

    #[test]
    fn encryption_flips_the_unset_log_default_but_never_an_explicit_choice() {
        let c: Config = toml::from_str("encrypt_at_rest = true\n").unwrap();
        assert_eq!(c.log_mode(), LogPastes::Off);
        let c: Config = toml::from_str("encrypt_at_rest = true\nlog_pastes = \"url\"\n").unwrap();
        assert_eq!(c.log_mode(), LogPastes::Url);
        let c: Config = toml::from_str("log_pastes = \"off\"\n").unwrap();
        assert_eq!(c.log_mode(), LogPastes::Off);
    }

    #[test]
    fn validate_rejects_nonsense() {
        let mut c = Config::default();
        c.listen_tcp.clear();
        assert!(c.validate().is_err());

        let c = Config {
            max_paste_bytes: 0,
            ..Config::default()
        };
        assert!(c.validate().is_err());

        let c = Config {
            total_deadline_secs: 1, // below idle timeout
            ..Config::default()
        };
        assert!(c.validate().is_err());

        let c = Config {
            base_url: String::new(),
            ..Config::default()
        };
        assert!(c.validate().is_err());

        let c = Config {
            base_url: "ftp://x".into(),
            ..Config::default()
        };
        assert!(c.validate().is_err());

        let c = Config {
            base_url: "https://x/".into(),
            ..Config::default()
        };
        assert!(c.validate().is_err(), "trailing slash must be rejected");

        let c = Config {
            base_url: "https:///x".into(),
            ..Config::default()
        };
        assert!(
            c.validate().is_err(),
            "authority-less base_url must be rejected"
        );

        let c = Config {
            base_url: "https://x/\"><script>".into(),
            ..Config::default()
        };
        assert!(
            c.validate().is_err(),
            "html-breaking chars in base_url must be rejected"
        );

        let c = Config {
            base_url: "http://".into(),
            ..Config::default()
        };
        assert!(c.validate().is_err(), "bare scheme must be rejected");

        let mut c = Config::default();
        c.quota_bytes = c.max_paste_bytes - 1; // quota smaller than one paste
        assert!(c.validate().is_err());

        let c = Config {
            gc_interval_secs: 0,
            ..Config::default()
        };
        assert!(c.validate().is_err());

        let c = Config {
            read_burst: 0.5,
            ..Config::default()
        };
        assert!(c.validate().is_err(), "read_burst below 1 must be rejected");

        let c = Config {
            read_rate_per_min: 0.0,
            ..Config::default()
        };
        assert!(
            c.validate().is_err(),
            "read_rate_per_min 0 must be rejected"
        );

        let c = Config {
            autoban_threshold: 0,
            ..Config::default()
        };
        assert!(
            c.validate().is_err(),
            "autoban_threshold 0 must be rejected"
        );

        let c = Config {
            autoban_window_secs: 0,
            ..Config::default()
        };
        assert!(
            c.validate().is_err(),
            "autoban_window_secs 0 must be rejected"
        );

        let c = Config {
            autoban_factor: 0.5,
            ..Config::default()
        };
        assert!(
            c.validate().is_err(),
            "autoban_factor below 1.0 must be rejected"
        );

        let c = Config {
            autoban_minutes: 30,
            autoban_max_minutes: 29,
            ..Config::default()
        };
        assert!(
            c.validate().is_err(),
            "autoban_max_minutes below autoban_minutes must be rejected when autoban is enabled"
        );
    }
}
