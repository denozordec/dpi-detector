use crate::config::AppConfig;
use crate::loader::TcpTarget;
use crate::metrics::{set_last_run_now, set_metric, SharedMetrics};
use futures::stream::{self, StreamExt};
use hickory_resolver::config::*;
use hickory_resolver::TokioAsyncResolver;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
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
}

#[derive(Default, Clone)]
pub struct TcpStats {
    pub total: i64,
    pub ok: i64,
    pub blocked: i64,
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
    }

    if run_tcp {
        let stats = run_tcp_check(cfg, tcp_targets).await;
        set_metric(metrics, "dpi_tcp_total", stats.total).await;
        set_metric(metrics, "dpi_tcp_ok", stats.ok).await;
        set_metric(metrics, "dpi_tcp_blocked", stats.blocked).await;
    }

    if run_sni {
        println!("[warn] test #4 (whitelist SNI) пока в минимальной реализации на Rust");
    }

    set_last_run_now(metrics).await;
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

        if !udp_ips.is_empty() && !doh_ips.is_empty() {
            let u: HashSet<_> = udp_ips.iter().collect();
            let d: HashSet<_> = doh_ips.iter().collect();
            if u != d {
                intercepted += 1;
            }
        }
    }

    let mut counts = std::collections::HashMap::<String, usize>::new();
    for ip in observed_udp_ips {
        *counts.entry(ip).or_default() += 1;
    }
    let stubs = counts
        .into_iter()
        .filter_map(|(ip, c)| if c >= 2 { Some(ip) } else { None })
        .collect::<HashSet<_>>();

    println!("[dns] intercepted {intercepted}/{total}");
    (stubs, intercepted, total)
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
            let mut blocked = false;
            let mut timed_out = false;

            if let Ok(lookup) = tokio::net::lookup_host((domain.as_str(), 443)).await {
                let ips = lookup.map(|s| s.ip().to_string()).collect::<Vec<_>>();
                if ips.iter().any(|ip| stub_ips.contains(ip)) {
                    blocked = true;
                }
            }

            if !blocked {
                let https_url = format!("https://{domain}");
                match timeout(timeout_dur, client.get(https_url).send()).await {
                    Ok(Ok(resp)) => {
                        let status = resp.status().as_u16();
                        if status == 451 || status >= 500 {
                            blocked = true;
                        } else if status == 200 {
                            if let Ok(body) = resp.bytes().await {
                                let inspect_len = body.len().min(body_limit);
                                let txt = String::from_utf8_lossy(&body[..inspect_len]).to_lowercase();
                                if txt.contains("blocked") || txt.contains("роскомнадзор") {
                                    blocked = true;
                                }
                            }
                        }
                    }
                    Ok(Err(_)) => blocked = true,
                    Err(_) => timed_out = true,
                }
            }

            if !blocked && !timed_out {
                let http_url = format!("http://{domain}");
                if timeout(timeout_dur, client.get(http_url).send()).await.is_err() {
                    timed_out = true;
                }
            }

            if timed_out {
                (0_i64, 0_i64, 1_i64)
            } else if blocked {
                (0_i64, 1_i64, 0_i64)
            } else {
                (1_i64, 0_i64, 0_i64)
            }
        }
    });

    let (ok, blocked, timeout_cnt) = stream
        .buffer_unordered(cfg.max_concurrent)
        .fold((0_i64, 0_i64, 0_i64), |acc, r| async move { (acc.0 + r.0, acc.1 + r.1, acc.2 + r.2) })
        .await;

    println!("[domains] total={total} ok={ok} blocked={blocked} timeout={timeout_cnt}");
    DomainStats {
        total,
        ok,
        blocked,
        timeout: timeout_cnt,
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
            let addr = format!("{}:{}", target.ip, target.port);
            let connect = timeout(timeout_dur, TcpStream::connect(addr)).await;
            let Ok(Ok(mut socket)) = connect else {
                return (0_i64, 1_i64);
            };

            let mut ok = true;
            let mut read_buf = [0_u8; 32];
            for _ in 0..16 {
                let mut chunk = vec![0_u8; 4000];
                for b in &mut chunk {
                    *b = rand::random::<u8>();
                }
                if socket.write_all(&chunk).await.is_err() {
                    ok = false;
                    break;
                }
                let _ = timeout(Duration::from_millis(200), socket.read(&mut read_buf)).await;
            }

            if ok {
                (1_i64, 0_i64)
            } else {
                (0_i64, 1_i64)
            }
        }
    });

    let (ok, blocked) = stream
        .buffer_unordered(cfg.max_concurrent)
        .fold((0_i64, 0_i64), |acc, r| async move { (acc.0 + r.0, acc.1 + r.1) })
        .await;

    println!("[tcp] total={total} ok={ok} blocked={blocked}");
    TcpStats { total, ok, blocked }
}
