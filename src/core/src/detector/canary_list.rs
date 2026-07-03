use super::types::{CanaryDomain, CanaryRole};
use anyhow::{Context, Result};
use std::path::Path;

pub fn load_canary_list(path: &Path) -> Result<Vec<CanaryDomain>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read canary list: {}", path.display()))?;

    let mut canaries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, ',');
        let domain = parts.next().unwrap_or("").trim().to_string();
        let role_str = parts.next().unwrap_or("").trim();
        let role = match role_str {
            "positive" => CanaryRole::Positive,
            "negative" => CanaryRole::Negative,
            other => {
                tracing::warn!("unknown canary role '{other}' for {domain}, skipping");
                continue;
            }
        };
        if !domain.is_empty() {
            canaries.push(CanaryDomain { domain, role });
        }
    }
    Ok(canaries)
}
