mod config;
mod loader;
mod metrics;
mod scanners;

use crate::config::{AppConfig, RunMode};
use crate::loader::{load_domains, load_tcp_targets, load_whitelist_sni};
use crate::metrics::{new_metrics, start_metrics_server};
use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::time::sleep;

fn base_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("failed to detect current executable path")?;
    let exe_dir = exe
        .parent()
        .map(|p| p.to_path_buf())
        .context("failed to detect executable directory")?;
    Ok(exe_dir)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = AppConfig::from_env();
    let mode_label = match cfg.run_mode {
        RunMode::Once => "once",
        RunMode::Schedule => "schedule",
    };
    println!("DPI Detector v3.0.0");
    println!("Параллельных запросов: {}", cfg.max_concurrent);
    println!("Режим: {}  Тесты: {}", mode_label, cfg.tests);
    if cfg.run_mode == RunMode::Schedule {
        println!("Интервал: {}s", cfg.check_interval.as_secs());
    }

    let workdir = base_dir().unwrap_or_else(|_| PathBuf::from("."));
    let domains = load_domains(&workdir.join("domains.txt")).context("domains.txt load failed")?;
    let tcp_targets = load_tcp_targets(&workdir.join("tcp16.json")).context("tcp16.json load failed")?;
    let wl_sni = load_whitelist_sni(&workdir.join("whitelist_sni.txt")).unwrap_or_default();

    let metrics = new_metrics();
    let metrics_clone = metrics.clone();
    let metrics_port = cfg.metrics_port;
    let metrics_user = cfg.metrics_user.clone();
    let metrics_password = cfg.metrics_password.clone();
    tokio::spawn(async move {
        if let Err(err) = start_metrics_server(metrics_clone, metrics_port, metrics_user, metrics_password).await {
            eprintln!("[metrics] server error: {err}");
        }
    });

    match cfg.run_mode {
        RunMode::Once => {
            scanners::run_all_selected(&cfg, &metrics, &domains, &tcp_targets, &wl_sni).await;
            println!("Проверка завершена.");
        }
        RunMode::Schedule => loop {
            scanners::run_all_selected(&cfg, &metrics, &domains, &tcp_targets, &wl_sni).await;
            println!("Следующий прогон через {}s...", cfg.check_interval.as_secs());
            sleep(cfg.check_interval).await;
        },
    }

    Ok(())
}
