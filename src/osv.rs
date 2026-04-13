use anyhow::{Context, Result};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};

use crate::parser::Dependency;

const OSV_BATCH_QUERY_URL: &str = "https://api.osv.dev/v1/querybatch";

#[derive(Debug, Serialize)]
struct OsvQuery {
    package: OsvPackage,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

#[derive(Debug, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Serialize)]
struct OsvBatchQuery {
    queries: Vec<OsvQuery>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Vulnerability {
    pub id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub details: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub severity: Vec<Severity>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Severity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DependencyReport {
    pub dependency: Dependency,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<Vulnerability>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvResponse>,
}

pub struct OsvService {
    client: reqwest::Client,
}

impl OsvService {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    pub async fn check_dependencies(
        &self,
        dependencies: &[Dependency],
    ) -> Result<Vec<DependencyReport>> {
        if dependencies.is_empty() {
            return Ok(Vec::new());
        }

        info!("Checking {} dependencies against OSV", dependencies.len());

        let queries: Vec<OsvQuery> = dependencies
            .iter()
            .map(|dep| OsvQuery {
                version: if dep.version.is_empty() {
                    None
                } else {
                    Some(dep.version.clone())
                },
                package: OsvPackage {
                    name: dep.name.clone(),
                    ecosystem: dep.ecosystem.clone(),
                },
            })
            .collect();

        let batch = OsvBatchQuery { queries };

        debug!("Sending batch query: {}", serde_json::to_string(&batch)?);

        let response = self
            .client
            .post(OSV_BATCH_QUERY_URL)
            .json(&batch)
            .send()
            .await
            .context("Failed to send request to OSV API")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("OSV API returned {}: {}", status, body);
            anyhow::bail!("OSV API returned {}: {}", status, body);
        }

        let batch_response: OsvBatchResponse = response
            .json()
            .await
            .context("Failed to deserialize OSV API response")?;

        let reports: Vec<DependencyReport> = dependencies
            .iter()
            .zip(batch_response.results)
            .map(|(dep, result)| {
                let vuln_count = result.vulns.len();
                if vuln_count > 0 {
                    info!(
                        "Found {} vulnerabilities for {}@{}",
                        vuln_count, dep.name, dep.version
                    );
                } else {
                    debug!("No vulnerabilities for {}@{}", dep.name, dep.version);
                }

                DependencyReport {
                    dependency: dep.clone(),
                    vulnerabilities: result.vulns,
                }
            })
            .collect();

        Ok(reports)
    }
}
