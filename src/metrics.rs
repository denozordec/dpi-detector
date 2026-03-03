use anyhow::Result;
use base64::Engine;
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

#[derive(Default, Clone)]
pub struct MetricsState {
    pub numbers: HashMap<&'static str, i64>,
    pub last_run_ts: f64,
    pub domain_status: HashMap<String, DomainStatus>,
    pub tcp_target_status: HashMap<String, TcpTargetStatus>,
}

#[derive(Default, Clone)]
pub struct DomainStatus {
    pub http: String,
    pub tls12: String,
    pub tls13: String,
    pub https: String,
}

#[derive(Default, Clone)]
pub struct TcpTargetStatus {
    pub provider: String,
    pub asn: String,
    pub status: String,
}

pub type SharedMetrics = Arc<RwLock<MetricsState>>;

pub fn new_metrics() -> SharedMetrics {
    Arc::new(RwLock::new(MetricsState::default()))
}

pub async fn set_metric(metrics: &SharedMetrics, key: &'static str, value: i64) {
    let mut m = metrics.write().await;
    m.numbers.insert(key, value);
}

pub async fn set_last_run_now(metrics: &SharedMetrics) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let mut m = metrics.write().await;
    m.last_run_ts = now;
}

pub async fn set_domain_statuses(metrics: &SharedMetrics, statuses: Vec<(String, DomainStatus)>) {
    let mut m = metrics.write().await;
    m.domain_status.clear();
    for (domain, status) in statuses {
        m.domain_status.insert(domain, status);
    }
}

pub async fn set_tcp_target_statuses(metrics: &SharedMetrics, statuses: Vec<(String, TcpTargetStatus)>) {
    let mut m = metrics.write().await;
    m.tcp_target_status.clear();
    for (target_id, status) in statuses {
        m.tcp_target_status.insert(target_id, status);
    }
}

fn escape_label(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn render(m: &MetricsState) -> String {
    let mut lines = Vec::new();
    let names = [
        ("dpi_dns_total", "Total DNS domains checked"),
        ("dpi_dns_intercepted", "DNS domains intercepted/replaced by ISP"),
        ("dpi_dns_ok", "DNS domains resolving correctly"),
        ("dpi_domains_total", "Total domains tested"),
        ("dpi_domains_ok", "Domains accessible"),
        ("dpi_domains_blocked", "Domains blocked"),
        ("dpi_domains_timeout", "Domains timed out"),
        ("dpi_domains_dns_fail", "Domains with DNS resolution failure"),
        ("dpi_tcp_total", "Total TCP probes"),
        ("dpi_tcp_ok", "TCP probes passed"),
        ("dpi_tcp_blocked", "TCP probes blocked"),
        ("dpi_tcp_mixed", "TCP probes with mixed results"),
    ];

    for (name, help) in names {
        if let Some(value) = m.numbers.get(name) {
            lines.push(format!("# HELP {name} {help}"));
            lines.push(format!("# TYPE {name} gauge"));
            lines.push(format!("{name} {value}"));
        }
    }

    lines.push("# HELP dpi_last_run_timestamp_seconds Unix timestamp of last completed test run".to_string());
    lines.push("# TYPE dpi_last_run_timestamp_seconds gauge".to_string());
    lines.push(format!("dpi_last_run_timestamp_seconds {:.3}", m.last_run_ts));

    if !m.domain_status.is_empty() {
        lines.push("# HELP dpi_domain_available Per-domain availability status (HTTPS overall, 1=current state)".to_string());
        lines.push("# TYPE dpi_domain_available gauge".to_string());
        let mut items = m.domain_status.iter().collect::<Vec<_>>();
        items.sort_by(|a, b| a.0.cmp(b.0));
        for (domain, st) in &items {
            lines.push(format!(
                "dpi_domain_available{{domain=\"{}\",status=\"{}\"}} 1",
                escape_label(domain),
                escape_label(&st.https)
            ));
        }

        lines.push("# HELP dpi_domain_ok Per-domain reachability: 1=ok, 0=not ok".to_string());
        lines.push("# TYPE dpi_domain_ok gauge".to_string());
        for (domain, st) in &items {
            let ok = if st.https == "ok" { 1 } else { 0 };
            lines.push(format!(
                "dpi_domain_ok{{domain=\"{}\"}} {ok}",
                escape_label(domain),
            ));
        }

        lines.push("# HELP dpi_domain_tls_status Per-domain TLS version status".to_string());
        lines.push("# TYPE dpi_domain_tls_status gauge".to_string());
        for (domain, st) in &items {
            lines.push(format!(
                "dpi_domain_tls_status{{domain=\"{}\",tls_version=\"1.2\",status=\"{}\"}} 1",
                escape_label(domain),
                escape_label(&st.tls12)
            ));
            lines.push(format!(
                "dpi_domain_tls_status{{domain=\"{}\",tls_version=\"1.3\",status=\"{}\"}} 1",
                escape_label(domain),
                escape_label(&st.tls13)
            ));
        }
    }

    if !m.tcp_target_status.is_empty() {
        lines.push("# HELP dpi_tcp_target_status Per-TCP-target DPI status (1=current state)".to_string());
        lines.push("# TYPE dpi_tcp_target_status gauge".to_string());
        let mut items = m.tcp_target_status.iter().collect::<Vec<_>>();
        items.sort_by(|a, b| a.0.cmp(b.0));
        for (tid, st) in &items {
            lines.push(format!(
                "dpi_tcp_target_status{{id=\"{}\",provider=\"{}\",asn=\"{}\",status=\"{}\"}} 1",
                escape_label(tid),
                escape_label(&st.provider),
                escape_label(&st.asn),
                escape_label(&st.status)
            ));
        }

        lines.push("# HELP dpi_tcp_target_ok Per-TCP-target: 1=ok (DPI not detected), 0=blocked/mixed".to_string());
        lines.push("# TYPE dpi_tcp_target_ok gauge".to_string());
        for (tid, st) in &items {
            let ok = if st.status == "ok" { 1 } else { 0 };
            lines.push(format!(
                "dpi_tcp_target_ok{{id=\"{}\",provider=\"{}\",asn=\"{}\"}} {ok}",
                escape_label(tid),
                escape_label(&st.provider),
                escape_label(&st.asn)
            ));
        }
    }

    lines.join("\n") + "\n"
}

fn text_response(code: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(code)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"internal error"))))
}

pub async fn start_metrics_server(
    metrics: SharedMetrics,
    port: u16,
    user: Option<String>,
    password: Option<String>,
) -> Result<()> {
    let auth = if let (Some(u), Some(p)) = (user, password) {
        Some(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
        ))
    } else {
        None
    };

    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    println!("[metrics] endpoint: http://0.0.0.0:{port}/metrics");

    loop {
        let (stream, _) = listener.accept().await?;
        let metrics = metrics.clone();
        let auth = auth.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| {
                let metrics = metrics.clone();
                let auth = auth.clone();
                async move {
                    if req.method() != Method::GET {
                        return Ok::<_, hyper::Error>(text_response(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed"));
                    }

                    if let Some(expected) = &auth {
                        let provided = req
                            .headers()
                            .get(AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        if provided != expected {
                            let resp = Response::builder()
                                .status(StatusCode::UNAUTHORIZED)
                                .header(WWW_AUTHENTICATE, "Basic realm=\"DPI Detector Metrics\"")
                                .body(Full::new(Bytes::from_static(b"Unauthorized")))
                                .unwrap_or_else(|_| text_response(StatusCode::UNAUTHORIZED, "Unauthorized"));
                            return Ok(resp);
                        }
                    }

                    match req.uri().path() {
                        "/metrics" | "/metrics/" => {
                            let snapshot = metrics.read().await.clone();
                            Ok(text_response(StatusCode::OK, &render(&snapshot)))
                        }
                        "/" | "/health" => Ok(text_response(StatusCode::OK, "OK")),
                        _ => Ok(text_response(StatusCode::NOT_FOUND, "Not found")),
                    }
                }
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("[metrics] connection error: {err}");
            }
        });
    }
}
