use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Deserialize)]
pub struct TcpTarget {
    pub id: String,
    pub ip: String,
    pub provider: String,
    #[serde(default)]
    pub asn: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub sni: String,
}

fn default_port() -> u16 {
    443
}

pub fn load_domains(path: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(path).with_context(|| format!("failed to read {:?}", path))?;
    let domains = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    Ok(domains)
}

pub fn load_whitelist_sni(path: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(path).with_context(|| format!("failed to read {:?}", path))?;
    let list = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    Ok(list)
}

pub fn load_tcp_targets(path: &Path) -> Result<Vec<TcpTarget>> {
    let content = fs::read_to_string(path).with_context(|| format!("failed to read {:?}", path))?;
    let targets = serde_json::from_str::<Vec<TcpTarget>>(&content)
        .with_context(|| format!("invalid JSON in {:?}", path))?;
    Ok(targets)
}
