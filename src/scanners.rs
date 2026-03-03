use crate::config::AppConfig;
use crate::loader::TcpTarget;
use crate::metrics::{
    set_domain_statuses, set_last_run_now, set_metric, set_tcp_target_statuses, DomainStatus, SharedMetrics,
    TcpTargetStatus,
};
use futures::stream::{self, StreamExt};
use hickory_resolver::config::*;
use hickory_resolver::TokioAsyncResolver;
use rand::distributions::{Alphanumeric, DistString};
use reqwest::Client;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout, Duration};
use tokio_rustls::TlsConnector;

#[derive(Default, Clone)]
pub struct DomainStats {
    pub total: i64,
    pub ok: i64,
    pub blocked: i64,
    pub timeout: i64,
    pub dns_fail: i64,
    pub per_domain: Vec<(String, DomainStatus)>,
}

#[derive(Default, Clone)]
pub struct TcpStats {
    pub total: i64,
    pub ok: i64,
    pub blocked: i64,
    pub mixed: i64,
    pub per_target: Vec<(String, TcpTargetStatus)>,
    pub raw_rows: Vec<Vec<String>>,
}

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Status")]
    status: Option<u32>,
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

fn color_status(value: &str) -> &'static str {
    let upper = value.to_uppercase();
    if upper.contains("OK") || upper.contains("REDIR") {
        "\x1b[1;32m"
    } else if upper.contains("TIMEOUT") || upper.contains("MIXED") {
        "\x1b[1;33m"
    } else if upper.contains("BLOCK")
        || upper.contains("DETECTED")
        || upper.contains("RST")
        || upper.contains("ABORT")
        || upper.contains("DNS FAIL")
        || upper.contains("DNS FAKE")
        || upper.contains("ISP PAGE")
    {
        "\x1b[1;31m"
    } else {
        "\x1b[0m"
    }
}

fn pad_cell(value: &str, width: usize) -> String {
    let len = value.chars().count();
    if len >= width {
        value.to_string()
    } else {
        format!("{value}{}", " ".repeat(width - len))
    }
}

fn draw_line(widths: &[usize], left: &str, mid: &str, right: &str, fill: &str) {
    let mut line = String::from(left);
    for (i, w) in widths.iter().enumerate() {
        line.push_str(&fill.repeat(*w + 2));
        if i + 1 == widths.len() {
            line.push_str(right);
        } else {
            line.push_str(mid);
        }
    }
    println!("{line}");
}

fn draw_table(headers: &[&str], rows: &[Vec<String>], status_cols: &[usize], dim_cols: &[usize]) {
    if headers.is_empty() {
        return;
    }
    let mut widths = headers.iter().map(|h| h.chars().count()).collect::<Vec<_>>();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }

    draw_line(&widths, "┌", "┬", "┐", "─");
    let mut header = String::from("│");
    for (i, h) in headers.iter().enumerate() {
        header.push(' ');
        header.push_str("\x1b[1;35m");
        header.push_str(&pad_cell(h, widths[i]));
        header.push_str("\x1b[0m");
        header.push(' ');
        header.push('│');
    }
    println!("{header}");
    draw_line(&widths, "├", "┼", "┤", "─");

    for row in rows {
        let mut line = String::from("│");
        for (i, cell) in row.iter().enumerate() {
            line.push(' ');
            if status_cols.contains(&i) {
                line.push_str(color_status(cell));
                line.push_str(&pad_cell(cell, widths[i]));
                line.push_str("\x1b[0m");
            } else if dim_cols.contains(&i) {
                line.push_str("\x1b[2m");
                line.push_str(&pad_cell(cell, widths[i]));
                line.push_str("\x1b[0m");
            } else if i == 0 {
                line.push_str("\x1b[36m");
                line.push_str(&pad_cell(cell, widths[i]));
                line.push_str("\x1b[0m");
            } else {
                line.push_str(&pad_cell(cell, widths[i]));
            }
            line.push(' ');
            line.push('│');
        }
        println!("{line}");
    }
    draw_line(&widths, "└", "┴", "┘", "─");
}

fn render_section_title(title: &str, total: usize, timeout: Duration) {
    println!(
        "\n\x1b[1m{}\x1b[0m  Целей: {} | timeout: {:.1}s",
        title,
        total,
        timeout.as_secs_f32()
    );
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

fn build_dangerous_tls_connector() -> TlsConnector {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

pub async fn run_all_selected(
    cfg: &AppConfig,
    metrics: &SharedMetrics,
    domains: &[String],
    tcp_targets: &[TcpTarget],
    _wl_sni: &[String],
) {
    let run_dns = cfg.tests.contains('1');
    let run_domains = cfg.tests.contains('2');
    let run_tcp = cfg.tests.contains('3');
    let run_sni = cfg.tests.contains('4');

    println!("[run] tests={}, concurrent={}", cfg.tests, cfg.max_concurrent);

    let mut stub_ips = HashSet::new();
    if run_dns {
        let (stubs, intercepted, total_dns) = run_dns_check(cfg).await;
        stub_ips = stubs;
        set_metric(metrics, "dpi_dns_total", total_dns).await;
        set_metric(metrics, "dpi_dns_intercepted", intercepted).await;
        set_metric(metrics, "dpi_dns_ok", total_dns - intercepted).await;
    }

    if run_domains {
        let stats = run_domains_check(cfg, domains, &stub_ips).await;
        set_metric(metrics, "dpi_domains_total", stats.total).await;
        set_metric(metrics, "dpi_domains_ok", stats.ok).await;
        set_metric(metrics, "dpi_domains_blocked", stats.blocked).await;
        set_metric(metrics, "dpi_domains_timeout", stats.timeout).await;
        set_metric(metrics, "dpi_domains_dns_fail", stats.dns_fail).await;
        set_domain_statuses(metrics, stats.per_domain.clone()).await;
    }

    if run_tcp {
        let stats = run_tcp_check(cfg, tcp_targets).await;
        set_metric(metrics, "dpi_tcp_total", stats.total).await;
        set_metric(metrics, "dpi_tcp_ok", stats.ok).await;
        set_metric(metrics, "dpi_tcp_blocked", stats.blocked).await;
        set_metric(metrics, "dpi_tcp_mixed", stats.mixed).await;
        set_tcp_target_statuses(metrics, stats.per_target.clone()).await;
    }

    if run_sni {
        run_whitelist_sni_test(cfg, tcp_targets, _wl_sni).await;
    }

    set_last_run_now(metrics).await;
}

fn classify_domain_state(http: &str, tls12: &str, tls13: &str) -> DomainStatus {
    fn norm(x: &str) -> &'static str {
        if x.contains("DNS FAIL") {
            "dns_fail"
        } else if x.contains("TIMEOUT") {
            "timeout"
        } else if x.contains("BLOCKED")
            || x.contains("TLS DPI")
            || x.contains("TLS MITM")
            || x.contains("TLS BLOCK")
            || x.contains("ISP PAGE")
            || x.contains("TCP RST")
            || x.contains("TCP ABORT")
        {
            "blocked"
        } else if x.contains("OK") || x.contains("REDIR") {
            "ok"
        } else {
            "unknown"
        }
    }

    let http_s = norm(http);
    let t12_s = norm(tls12);
    let t13_s = norm(tls13);
    let https = if t12_s == "ok" || t13_s == "ok" {
        "ok"
    } else if t12_s == "blocked" || t13_s == "blocked" {
        "blocked"
    } else if t12_s == "timeout" || t13_s == "timeout" {
        "timeout"
    } else if t12_s == "dns_fail" || t13_s == "dns_fail" {
        "dns_fail"
    } else {
        "unknown"
    };
    DomainStatus {
        http: http_s.to_string(),
        tls12: t12_s.to_string(),
        tls13: t13_s.to_string(),
        https: https.to_string(),
    }
}

pub async fn run_dns_check(cfg: &AppConfig) -> (HashSet<String>, i64, i64) {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .unwrap_or_else(|_| TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default()));
    let client = Client::builder()
        .use_rustls_tls()
        .danger_accept_invalid_certs(true)
        .timeout(cfg.timeout)
        .build()
        .unwrap_or_else(|_| Client::new());

    let total = cfg.dns_domains.len() as i64;
    let mut intercepted = 0_i64;
    let mut observed_udp_ips = Vec::new();
    let mut rows: Vec<(String, String, String, String)> = Vec::new();

    render_section_title("[Проверка подмены DNS]", cfg.dns_domains.len(), cfg.timeout);
    println!("Проверяем, перехватывает ли провайдер DNS-запросы...");

    for domain in &cfg.dns_domains {
        let udp_ips = resolver
            .lookup_ip(*domain)
            .await
            .ok()
            .map(|ips| ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>())
            .unwrap_or_default();
        observed_udp_ips.extend(udp_ips.iter().cloned());

        let mut doh_ips = Vec::new();
        for url in &cfg.dns_doh_servers {
            if let Ok(resp) = client
                .get(*url)
                .query(&[("name", *domain), ("type", "A")])
                .header("accept", "application/dns-json")
                .send()
                .await
            {
                if resp.status().is_success() {
                    if let Ok(json) = resp.json::<DohResponse>().await {
                        if json.status.unwrap_or(0) == 3 {
                            break;
                        }
                        if let Some(ans) = json.answer {
                            doh_ips = ans
                                .into_iter()
                                .filter(|a| a.record_type == 1)
                                .map(|a| a.data)
                                .collect::<Vec<_>>();
                            if !doh_ips.is_empty() {
                                break;
                            }
                        }
                    }
                }
            }
        }

        let udp_str = if udp_ips.is_empty() {
            "—".to_string()
        } else {
            udp_ips.iter().take(2).cloned().collect::<Vec<_>>().join(", ")
        };
        let doh_str = if doh_ips.is_empty() {
            "—".to_string()
        } else {
            doh_ips.iter().take(2).cloned().collect::<Vec<_>>().join(", ")
        };

        let mut row_status = "DNS OK".to_string();
        if !udp_ips.is_empty() && !doh_ips.is_empty() {
            let u: HashSet<_> = udp_ips.iter().collect();
            let d: HashSet<_> = doh_ips.iter().collect();
            if u != d {
                intercepted += 1;
                row_status = "DNS ПОДМЕНА".to_string();
            }
        } else if udp_ips.is_empty() || doh_ips.is_empty() {
            row_status = "НЕПОЛНЫЕ ДАННЫЕ".to_string();
        }

        rows.push((domain.to_string(), doh_str, udp_str, row_status));
    }

    let mut counts = std::collections::HashMap::<String, usize>::new();
    for ip in observed_udp_ips {
        *counts.entry(ip).or_default() += 1;
    }
    let stubs = counts
        .into_iter()
        .filter_map(|(ip, c)| if c >= 2 { Some(ip) } else { None })
        .collect::<HashSet<_>>();

    let table_rows = rows
        .into_iter()
        .map(|(domain, doh, udp, status)| vec![domain, doh, udp, status])
        .collect::<Vec<_>>();
    draw_table(&["Домен", "DoH", "UDP DNS", "Статус"], &table_rows, &[3], &[]);
    println!("[dns] intercepted {intercepted}/{total}");
    (stubs, intercepted, total)
}

async fn check_https(client: &Client, domain: &str, timeout_dur: Duration, body_limit: usize) -> String {
    let https_url = format!("https://{domain}");
    match timeout(timeout_dur, client.get(https_url).send()).await {
        Ok(Ok(resp)) => {
            let status = resp.status().as_u16();
            let location = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();
            if status == 451 {
                return "BLOCKED".to_string();
            }
            if !location.is_empty()
                && (location.contains("warning.rt.ru")
                    || location.contains("lawfilter")
                    || location.contains("rkn.gov.ru")
                    || location.contains("block"))
            {
                return "ISP PAGE".to_string();
            }
            if status == 200 {
                if let Ok(body) = resp.bytes().await {
                    let inspect_len = body.len().min(body_limit);
                    let txt = String::from_utf8_lossy(&body[..inspect_len]).to_lowercase();
                    if txt.contains("blocked")
                        || txt.contains("роскомнадзор")
                        || txt.contains("единый реестр")
                    {
                        return "ISP PAGE".to_string();
                    }
                }
            }
            if (200..500).contains(&status) {
                "OK".to_string()
            } else {
                format!("OK {status}")
            }
        }
        Ok(Err(_)) => "TLS BLOCK".to_string(),
        Err(_) => "TIMEOUT".to_string(),
    }
}

async fn check_http(client: &Client, domain: &str, timeout_dur: Duration, body_limit: usize) -> String {
    let http_url = format!("http://{domain}");
    match timeout(timeout_dur, client.get(http_url).send()).await {
        Ok(Ok(resp)) => {
            let status = resp.status().as_u16();
            let location = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();
            if status == 451 {
                return "BLOCKED".to_string();
            }
            if !location.is_empty()
                && (location.contains("warning.rt.ru")
                    || location.contains("lawfilter")
                    || location.contains("rkn.gov.ru")
                    || location.contains("block"))
            {
                return "ISP PAGE".to_string();
            }
            if status == 200 {
                if let Ok(body) = resp.bytes().await {
                    let inspect_len = body.len().min(body_limit);
                    let txt = String::from_utf8_lossy(&body[..inspect_len]).to_lowercase();
                    if txt.contains("blocked")
                        || txt.contains("роскомнадзор")
                        || txt.contains("единый реестр")
                    {
                        return "ISP PAGE".to_string();
                    }
                }
            }
            if (200..300).contains(&status) {
                "OK".to_string()
            } else if (300..400).contains(&status) {
                "REDIR".to_string()
            } else {
                format!("OK {status}")
            }
        }
        Ok(Err(_)) => "CONN ERR".to_string(),
        Err(_) => "TIMEOUT".to_string(),
    }
}

pub async fn run_domains_check(cfg: &AppConfig, domains: &[String], stub_ips: &HashSet<String>) -> DomainStats {
    let sem = Arc::new(Semaphore::new(cfg.max_concurrent));
    let client = Client::builder()
        .use_rustls_tls()
        .danger_accept_invalid_certs(true)
        .timeout(cfg.timeout)
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(0)
        .build()
        .unwrap_or_else(|_| Client::new());

    let total = domains.len() as i64;
    let stream = stream::iter(domains.iter().cloned()).map(|domain| {
        let sem = sem.clone();
        let client = client.clone();
        let stub_ips = stub_ips.clone();
        let timeout_dur = cfg.timeout;
        let body_limit = cfg.body_inspect_limit;
        async move {
            let _permit = sem.acquire().await.ok();
            let mut dns_fake_or_fail = false;
            let mut dns_fail = false;
            let domain_for_lookup = domain.clone();

            if let Ok(lookup) = tokio::net::lookup_host((domain_for_lookup.as_str(), 443)).await {
                let ips = lookup.map(|s| s.ip().to_string()).collect::<Vec<_>>();
                if ips.iter().any(|ip| stub_ips.contains(ip)) {
                    let status = DomainStatus {
                        http: "dns_fail".to_string(),
                        tls12: "dns_fail".to_string(),
                        tls13: "dns_fail".to_string(),
                        https: "dns_fail".to_string(),
                    };
                    return (domain, status, "DNS FAKE".to_string(), "DNS FAKE".to_string(), "DNS FAKE".to_string());
                }
                if ips.is_empty() {
                    dns_fake_or_fail = true;
                    dns_fail = true;
                }
            } else {
                dns_fake_or_fail = true;
                dns_fail = true;
            }

            if dns_fake_or_fail {
                let status = DomainStatus {
                    http: if dns_fail { "dns_fail" } else { "blocked" }.to_string(),
                    tls12: if dns_fail { "dns_fail" } else { "blocked" }.to_string(),
                    tls13: if dns_fail { "dns_fail" } else { "blocked" }.to_string(),
                    https: if dns_fail { "dns_fail" } else { "blocked" }.to_string(),
                };
                return (domain, status, "DNS FAIL".to_string(), "DNS FAIL".to_string(), "DNS FAIL".to_string());
            }

            // reqwest не разделяет TLS 1.2/1.3 в простом API, поэтому делаем 2 независимые
            // HTTPS проверки и сопоставляем их с колонками TLS1.2/TLS1.3.
            let tls12 = check_https(&client, &domain, timeout_dur, body_limit).await;
            let tls13 = check_https(&client, &domain, timeout_dur, body_limit).await;
            let http = check_http(&client, &domain, timeout_dur, body_limit).await;

            let status = classify_domain_state(&http, &tls12, &tls13);
            (domain, status, http, tls12, tls13)
        }
    });

    let rows = stream
        .buffer_unordered(cfg.max_concurrent)
        .collect::<Vec<_>>()
        .await;

    let mut ok = 0_i64;
    let mut blocked = 0_i64;
    let mut timeout_cnt = 0_i64;
    let mut dns_fail = 0_i64;
    let mut per_domain = Vec::with_capacity(rows.len());
    let mut view_rows: Vec<(String, String, String, String, String)> = Vec::with_capacity(rows.len());

    render_section_title("[Проверка доступности доменов]", domains.len(), cfg.timeout);
    for (domain, status, http, tls12, tls13) in rows {
        let detail = status.https.clone();
        match status.https.as_str() {
            "ok" => ok += 1,
            "blocked" => blocked += 1,
            "timeout" => timeout_cnt += 1,
            "dns_fail" => dns_fail += 1,
            _ => {}
        }
        view_rows.push((domain.clone(), http, tls12, tls13, detail));
        per_domain.push((domain, status));
    }

    view_rows.sort_by(|a, b| a.0.cmp(&b.0));
    let table_rows = view_rows
        .into_iter()
        .map(|(domain, http, tls12, tls13, detail)| vec![domain, http, tls12, tls13, detail])
        .collect::<Vec<_>>();
    draw_table(
        &["Домен", "HTTP", "TLS1.2", "TLS1.3", "Детали"],
        &table_rows,
        &[1, 2, 3],
        &[4],
    );

    println!(
        "[domains] total={total} ok={ok} blocked={blocked} timeout={timeout_cnt} dns_fail={dns_fail}"
    );
    DomainStats {
        total,
        ok,
        blocked,
        timeout: timeout_cnt,
        dns_fail,
        per_domain,
    }
}

async fn run_fat_sequence<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    host: &str,
    timeout_dur: Duration,
) -> (String, String, String) {
    let mut alive = false;
    let mut read_buf = [0_u8; 1024];

    for i in 0..16 {
        let mut request = format!(
            "HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: dpi-detector-rust/3\r\nConnection: keep-alive\r\n"
        );
        if i > 0 {
            let pad = Alphanumeric.sample_string(&mut rand::thread_rng(), 4000);
            request.push_str(&format!("X-Pad: {pad}\r\n"));
        }
        request.push_str("\r\n");

        match timeout(timeout_dur, stream.write_all(request.as_bytes())).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => {
                if i == 0 {
                    return ("Нет".to_string(), "ERR".to_string(), "connect_error".to_string());
                }
                let alive_str = if alive { "Да" } else { "Нет" };
                return (
                    alive_str.to_string(),
                    "DETECTED".to_string(),
                    format!("Conn Err at {}KB", i * 4),
                );
            }
            Err(_) => {
                if i == 0 {
                    return ("Нет".to_string(), "ERR".to_string(), "timeout".to_string());
                }
                let alive_str = if alive { "Да" } else { "Нет" };
                return (
                    alive_str.to_string(),
                    "DETECTED".to_string(),
                    format!("Blackhole at {}KB", i * 4),
                );
            }
        }

        match timeout(timeout_dur, stream.read(&mut read_buf)).await {
            Ok(Ok(n)) if n > 0 => {
                if i == 0 {
                    alive = true;
                }
            }
            Ok(Ok(_)) | Ok(Err(_)) => {
                if i == 0 {
                    return ("Нет".to_string(), "ERR".to_string(), "read_error".to_string());
                }
                let alive_str = if alive { "Да" } else { "Нет" };
                return (
                    alive_str.to_string(),
                    "DETECTED".to_string(),
                    format!("Conn Err at {}KB", i * 4),
                );
            }
            Err(_) => {
                if i == 0 {
                    return ("Нет".to_string(), "ERR".to_string(), "timeout".to_string());
                }
                let alive_str = if alive { "Да" } else { "Нет" };
                return (
                    alive_str.to_string(),
                    "DETECTED".to_string(),
                    format!("Blackhole at {}KB", i * 4),
                );
            }
        }

        sleep(Duration::from_millis(50)).await;
    }

    let alive_str = if alive { "Да" } else { "Нет" };
    (alive_str.to_string(), "OK".to_string(), "".to_string())
}

async fn probe_tcp_target(target: &TcpTarget, timeout_dur: Duration) -> (String, String, String) {
    let addr = format!("{}:{}", target.ip, target.port);
    let tcp = match timeout(timeout_dur, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => return ("Нет".to_string(), "ERR".to_string(), "connect_error".to_string()),
        Err(_) => return ("Нет".to_string(), "ERR".to_string(), "timeout".to_string()),
    };

    if target.port == 443 {
        let sni_host = if !target.sni.trim().is_empty() {
            target.sni.clone()
        } else {
            "example.com".to_string()
        };
        let server_name = match ServerName::try_from(sni_host.clone()) {
            Ok(n) => n,
            Err(_) => return ("Нет".to_string(), "ERR".to_string(), "invalid_sni".to_string()),
        };
        let connector = build_dangerous_tls_connector();
        let mut tls_stream = match timeout(timeout_dur, connector.connect(server_name, tcp)).await {
            Ok(Ok(s)) => s,
            Ok(Err(_)) => return ("Нет".to_string(), "ERR".to_string(), "tls_handshake_error".to_string()),
            Err(_) => return ("Нет".to_string(), "ERR".to_string(), "tls_handshake_timeout".to_string()),
        };
        run_fat_sequence(&mut tls_stream, &sni_host, timeout_dur).await
    } else {
        let host = if !target.sni.trim().is_empty() {
            target.sni.clone()
        } else {
            target.ip.clone()
        };
        let mut plain_stream = tcp;
        run_fat_sequence(&mut plain_stream, &host, timeout_dur).await
    }
}

pub async fn run_tcp_check(cfg: &AppConfig, targets: &[TcpTarget]) -> TcpStats {
    let sem = Arc::new(Semaphore::new(cfg.max_concurrent));
    let total = targets.len() as i64;

    let stream = stream::iter(targets.iter().cloned()).map(|target| {
        let sem = sem.clone();
        let timeout_dur = Duration::from_secs(8);
        async move {
            let _permit = sem.acquire().await.ok();
            let (alive, status, detail) = probe_tcp_target(&target, timeout_dur).await;
            (target, alive, status, detail)
        }
    });

    let rows = stream
        .buffer_unordered(cfg.max_concurrent)
        .collect::<Vec<_>>()
        .await;

    let mut ok = 0_i64;
    let mut blocked = 0_i64;
    let mut mixed = 0_i64;
    let mut per_target = Vec::with_capacity(rows.len());
    let mut raw_rows = Vec::with_capacity(rows.len());

    render_section_title("[Проверка TCP 16-20KB]", targets.len(), Duration::from_secs(8));
    let mut table_rows: Vec<(String, String, String, String, String, String)> = Vec::with_capacity(rows.len());
    for (target, alive, status, detail) in rows {
        let status_key = if status == "OK" {
            ok += 1;
            "ok"
        } else if status == "MIXED" {
            mixed += 1;
            "mixed"
        } else {
            blocked += 1;
            "blocked"
        };
        let asn_value = if target.asn.is_empty() { "-".to_string() } else { target.asn.clone() };
        table_rows.push((
            target.id.clone(),
            asn_value.clone(),
            target.provider.clone(),
            alive.clone(),
            status.clone(),
            if detail.is_empty() { "-".to_string() } else { detail.clone() },
        ));

        per_target.push((
            target.id.clone(),
            TcpTargetStatus {
                provider: target.provider.clone(),
                asn: asn_value.clone(),
                status: status_key.to_string(),
            },
        ));
        raw_rows.push(vec![
            target.id,
            asn_value,
            target.provider,
            alive,
            status,
            detail,
        ]);
    }

    table_rows.sort_by(|a, b| a.0.cmp(&b.0));
    let rows_fmt = table_rows
        .into_iter()
        .map(|(id, asn, provider, alive, status, detail)| vec![id, asn, provider, alive, status, detail])
        .collect::<Vec<_>>();
    draw_table(
        &["ID", "ASN", "Провайдер", "Alive", "Статус", "Детали"],
        &rows_fmt,
        &[4],
        &[5],
    );

    println!("[tcp] total={total} ok={ok} blocked={blocked} mixed={mixed}");
    TcpStats {
        total,
        ok,
        blocked,
        mixed,
        per_target,
        raw_rows,
    }
}

pub async fn run_whitelist_sni_test(cfg: &AppConfig, targets: &[TcpTarget], whitelist_sni: &[String]) {
    let port443 = targets
        .iter()
        .filter(|t| t.port == 443)
        .cloned()
        .collect::<Vec<_>>();
    if port443.is_empty() {
        println!("[sni] Нет целей с портом 443.");
        return;
    }
    if whitelist_sni.is_empty() {
        println!("[sni] whitelist_sni.txt пуст — тест пропущен.");
        return;
    }

    println!(
        "\n[sni] Поиск белых SNI: targets={} sni={}",
        port443.len(),
        whitelist_sni.len()
    );

    // Сначала определяем кандидатов (только DETECTED по базовому SNI).
    let mut blocked_by_asn: HashMap<String, TcpTarget> = HashMap::new();
    for target in &port443 {
        let timeout_dur = Duration::from_secs(8);
        let base = probe_tcp_target(target, timeout_dur).await;
        if base.1 == "DETECTED" {
            let key = if target.asn.trim().is_empty() {
                target.ip.clone()
            } else {
                target.asn.trim().to_string()
            };
            blocked_by_asn.entry(key).or_insert_with(|| target.clone());
        }
    }

    if blocked_by_asn.is_empty() {
        println!("[sni] Блокированных AS не найдено, перебор не требуется.");
        return;
    }

    let sem = Arc::new(Semaphore::new(cfg.max_concurrent));
    let mut found = 0usize;
    let mut total = 0usize;
    let mut rows: Vec<(String, String, String)> = Vec::new();
    for (asn_key, target) in blocked_by_asn {
        total += 1;
        let mut selected = String::new();
        let candidates = std::iter::once("".to_string())
            .chain(whitelist_sni.iter().cloned())
            .collect::<Vec<_>>();

        for sni in candidates {
            let _permit = sem.acquire().await.ok();
            let mut t = target.clone();
            t.sni = sni.clone();
            let (_alive, status, _detail) = probe_tcp_target(&t, Duration::from_secs(8)).await;
            if status == "OK" {
                selected = if sni.is_empty() { "(без SNI)".to_string() } else { sni };
                break;
            }
        }

        if selected.is_empty() {
            rows.push((asn_key, target.provider, "НЕ НАЙДЕН".to_string()));
        } else {
            found += 1;
            rows.push((asn_key, target.provider, selected));
        }
    }

    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let rows_fmt = rows
        .into_iter()
        .map(|(asn, provider, wl_sni)| vec![asn, provider, wl_sni])
        .collect::<Vec<_>>();
    draw_table(&["AS", "Провайдер", "WL SNI"], &rows_fmt, &[2], &[]);

    println!("[sni] Найдено белых SNI: {found}/{total}");
}
