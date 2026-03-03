use std::env;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub run_mode: RunMode,
    pub tests: String,
    pub check_interval: Duration,
    pub max_concurrent: usize,
    pub timeout: Duration,
    pub body_inspect_limit: usize,
    pub metrics_port: u16,
    pub metrics_user: Option<String>,
    pub metrics_password: Option<String>,
    pub dns_domains: Vec<&'static str>,
    pub dns_doh_servers: Vec<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunMode {
    Once,
    Schedule,
}

fn env_usize(name: &str, default: usize, min: usize, max: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|v| v.clamp(min, max))
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64, min: u64, max: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.clamp(min, max))
        .unwrap_or(default)
}

fn env_u16(name: &str, default: u16, min: u16, max: u16) -> u16 {
    env::var(name)
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .map(|v| v.clamp(min, max))
        .unwrap_or(default)
}

fn normalize_tests(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if matches!(ch, '1' | '2' | '3' | '4') && !out.contains(ch) {
            out.push(ch);
        }
    }
    if out.is_empty() {
        "123".to_string()
    } else {
        out
    }
}

impl AppConfig {
    pub fn from_env() -> Self {
        let run_mode = match env::var("RUN_MODE").unwrap_or_else(|_| "schedule".to_string()).as_str() {
            "once" => RunMode::Once,
            _ => RunMode::Schedule,
        };
        let tests = normalize_tests(&env::var("TESTS").unwrap_or_else(|_| "123".to_string()));
        let check_interval_secs = env_u64("CHECK_INTERVAL", 7200, 10, 86_400);
        let max_concurrent = env_usize("MAX_CONCURRENT", 30, 1, 2000);
        let timeout_secs = env_u64("TIMEOUT", 7, 1, 120);
        let body_inspect_limit = env_usize("BODY_INSPECT_LIMIT", 4096, 256, 1024 * 1024);
        let metrics_port = env_u16("METRICS_PORT", 9090, 1, 65535);

        let metrics_user = env::var("METRICS_USER").ok().filter(|v| !v.is_empty());
        let metrics_password = env::var("METRICS_PASSWORD").ok().filter(|v| !v.is_empty());

        Self {
            run_mode,
            tests,
            check_interval: Duration::from_secs(check_interval_secs),
            max_concurrent,
            timeout: Duration::from_secs(timeout_secs),
            body_inspect_limit,
            metrics_port,
            metrics_user,
            metrics_password,
            dns_domains: vec![
                "rutor.info",
                "ej.ru",
                "flibusta.is",
                "clubtone.do.am",
                "rezka.ag",
                "shikimori.one",
            ],
            dns_doh_servers: vec![
                "https://dns.google/resolve",
                "https://1.1.1.1/dns-query",
                "https://cloudflare-dns.com/dns-query",
            ],
        }
    }
}
