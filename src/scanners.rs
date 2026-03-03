use crate::config::AppConfig;
use crate::loader::TcpTarget;
use crate::metrics::{
    set_domain_statuses, set_last_run_now, set_metric, set_tcp_target_statuses, DomainStatus, SharedMetrics,
    TcpTargetStatus,
};
use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Attribute, Cell, Color, ContentArrangement, Table,
};
use futures::stream::{self, StreamExt};
use hickory_resolver::config::*;
use hickory_resolver::TokioAsyncResolver;
use reqwest::Client;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

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

fn status_cell(value: &str) -> Cell {
    let upper = value.to_uppercase();
    if upper.contains("OK") || upper.contains("REDIR") {
        Cell::new(value).fg(Color::Green).add_attribute(Attribute::Bold)
    } else if upper.contains("TIMEOUT") || upper.contains("MIXED") {
        Cell::new(value).fg(Color::Yellow).add_attribute(Attribute::Bold)
    } else if upper.contains("BLOCK")
        || upper.contains("DETECTED")
        || upper.contains("RST")
        || upper.contains("ABORT")
        || upper.contains("DNS FAIL")
        || upper.contains("DNS FAKE")
        || upper.contains("ISP PAGE")
    {
        Cell::new(value).fg(Color::Red).add_attribute(Attribute::Bold)
    } else {
        Cell::new(value).fg(Color::White)
    }
}

fn render_section_title(title: &str, total: usize, timeout: Duration) {
    println!(
        "\n{}  Целей: {} | timeout: {:.1}s",
        title,
        total,
        timeout.as_secs_f32()
    );
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

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Домен").fg(Color::Magenta).add_attribute(Attribute::Bold),
            Cell::new("DoH").fg(Color::Magenta).add_attribute(Attribute::Bold),
            Cell::new("UDP DNS").fg(Color::Magenta).add_attribute(Attribute::Bold),
            Cell::new("Статус").fg(Color::Magenta).add_attribute(Attribute::Bold),
        ]);
    for (domain, doh, udp, status) in rows {
        table.add_row(vec![
            Cell::new(domain).fg(Color::Cyan),
            Cell::new(doh).fg(Color::White),
            Cell::new(udp).fg(Color::White),
            status_cell(&status),
        ]);
    }
    println!("{table}");
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
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Домен").fg(Color::Magenta).add_attribute(Attribute::Bold),
            Cell::new("HTTP").fg(Color::Magenta).add_attribute(Attribute::Bold),
            Cell::new("TLS1.2").fg(Color::Magenta).add_attribute(Attribute::Bold),
            Cell::new("TLS1.3").fg(Color::Magenta).add_attribute(Attribute::Bold),
            Cell::new("Детали").fg(Color::Magenta).add_attribute(Attribute::Bold),
        ]);
    for (domain, http, tls12, tls13, detail) in view_rows {
        table.add_row(vec![
            Cell::new(domain).fg(Color::Cyan),
            status_cell(&http),
            status_cell(&tls12),
            status_cell(&tls13),
            Cell::new(detail).fg(Color::DarkGrey),
        ]);
    }
    println!("{table}");

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

async fn probe_tcp_target(target: &TcpTarget, timeout_dur: Duration) -> (String, String) {
    let addr = format!("{}:{}", target.ip, target.port);
    let connect = timeout(timeout_dur, TcpStream::connect(addr)).await;
    let Ok(Ok(mut socket)) = connect else {
        return ("DETECTED".to_string(), "connect_error".to_string());
    };

    let mut ok = true;
    let mut read_buf = [0_u8; 32];
    for i in 0..16 {
        let mut chunk = vec![0_u8; 4000];
        for b in &mut chunk {
            *b = rand::random::<u8>();
        }
        if socket.write_all(&chunk).await.is_err() {
            return ("DETECTED".to_string(), format!("write_err_at_{}KB", i * 4));
        }
        if timeout(Duration::from_millis(250), socket.read(&mut read_buf)).await.is_err() {
            ok = false;
        }
    }

    if ok {
        ("OK".to_string(), "".to_string())
    } else {
        ("MIXED".to_string(), "partial_timeout".to_string())
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
            let (status, detail) = probe_tcp_target(&target, timeout_dur).await;
            (target, status, detail)
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
    let mut table_rows: Vec<(String, String, String, String, String)> = Vec::with_capacity(rows.len());
    for (target, status, detail) in rows {
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
            status,
            detail,
        ]);
    }

    table_rows.sort_by(|a, b| a.0.cmp(&b.0));
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("ID").fg(Color::Magenta).add_attribute(Attribute::Bold),
            Cell::new("ASN").fg(Color::Magenta).add_attribute(Attribute::Bold),
            Cell::new("Провайдер").fg(Color::Magenta).add_attribute(Attribute::Bold),
            Cell::new("Статус").fg(Color::Magenta).add_attribute(Attribute::Bold),
            Cell::new("Детали").fg(Color::Magenta).add_attribute(Attribute::Bold),
        ]);
    for (id, asn, provider, status, detail) in table_rows {
        table.add_row(vec![
            Cell::new(id).fg(Color::White),
            Cell::new(asn).fg(Color::Yellow),
            Cell::new(provider).fg(Color::Cyan),
            status_cell(&status),
            Cell::new(detail).fg(Color::DarkGrey),
        ]);
    }
    println!("{table}");

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
        if base.0 == "DETECTED" {
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
            let (status, _) = probe_tcp_target(&t, Duration::from_secs(8)).await;
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
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("AS").fg(Color::Magenta).add_attribute(Attribute::Bold),
            Cell::new("Провайдер").fg(Color::Magenta).add_attribute(Attribute::Bold),
            Cell::new("WL SNI").fg(Color::Magenta).add_attribute(Attribute::Bold),
        ]);
    for (asn, provider, wl_sni) in rows {
        table.add_row(vec![
            Cell::new(asn).fg(Color::Yellow),
            Cell::new(provider).fg(Color::Cyan),
            status_cell(&wl_sni),
        ]);
    }
    println!("{table}");

    println!("[sni] Найдено белых SNI: {found}/{total}");
}
