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
        ("dpi_tcp_total", "Total TCP probes"),
        ("dpi_tcp_ok", "TCP probes passed"),
        ("dpi_tcp_blocked", "TCP probes blocked"),
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
