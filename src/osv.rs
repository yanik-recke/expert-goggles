use anyhow::{Context, Result};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};

use crate::parser::Dependency;

const OSV_BATCH_QUERY_URL: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL: &str = "https://api.osv.dev/v1/vulns";

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
struct OsvBatchVuln {
    id: String,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResult {
    #[serde(default)]
    vulns: Vec<OsvBatchVuln>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvBatchResult>,
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

        let mut reports = Vec::new();

        for (dep, result) in dependencies.iter().zip(batch_response.results) {
            if result.vulns.is_empty() {
                debug!("No vulnerabilities for {}@{}", dep.name, dep.version);
                reports.push(DependencyReport {
                    dependency: dep.clone(),
                    vulnerabilities: Vec::new(),
                });
                continue;
            }

            info!(
                "Found {} vulnerabilities for {}@{}, fetching details",
                result.vulns.len(),
                dep.name,
                dep.version
            );

            let mut vulns = Vec::new();
            for batch_vuln in &result.vulns {
                match self.fetch_vulnerability(&batch_vuln.id).await {
                    Ok(vuln) => vulns.push(vuln),
                    Err(e) => {
                        error!("Failed to fetch details for {}: {}", batch_vuln.id, e);
                    }
                }
            }

            reports.push(DependencyReport {
                dependency: dep.clone(),
                vulnerabilities: vulns,
            });
        }

        Ok(reports)
    }

    async fn fetch_vulnerability(&self, id: &str) -> Result<Vulnerability> {
        debug!("Fetching vulnerability details for {}", id);

        let response = self
            .client
            .get(format!("{}/{}", OSV_VULN_URL, id))
            .send()
            .await
            .context(format!("Failed to fetch vulnerability {}", id))?;

        if !response.status().is_success() {
            let status = response.status();
            anyhow::bail!("OSV API returned {} for vulnerability {}", status, id);
        }

        response
            .json()
            .await
            .context(format!("Failed to deserialize vulnerability {}", id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, version: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem: "Maven".to_string(),
        }
    }

    #[tokio::test]
    async fn check_empty_list() {
        let service = OsvService::new();
        let reports = service.check_dependencies(&[]).await.unwrap();
        assert!(reports.is_empty());
    }

    #[tokio::test]
    async fn check_vulnerable_dependency() {
        let service = OsvService::new();
        // log4j 2.14.1 is known to be affected by Log4Shell (CVE-2021-44228)
        let deps = vec![dep("org.apache.logging.log4j:log4j-core", "2.14.1")];

        let reports = service.check_dependencies(&deps).await.unwrap();
        assert_eq!(reports.len(), 1);
        assert!(
            !reports[0].vulnerabilities.is_empty(),
            "log4j 2.14.1 should have known vulnerabilities"
        );

        // OSV returns GHSA IDs; CVEs appear in the aliases field
        let has_log4shell = reports[0].vulnerabilities.iter().any(|v| {
            v.id.contains("CVE-2021-44228")
                || v.aliases.iter().any(|a| a.contains("CVE-2021-44228"))
        });
        assert!(
            has_log4shell,
            "Should reference Log4Shell (CVE-2021-44228) in id or aliases"
        );
    }

    #[tokio::test]
    async fn check_safe_dependency() {
        let service = OsvService::new();
        // Latest guava should have no (or very few) known vulnerabilities
        let deps = vec![dep("com.google.guava:guava", "33.0.0-jre")];

        let reports = service.check_dependencies(&deps).await.unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].dependency.name, "com.google.guava:guava");
    }

    #[tokio::test]
    async fn check_multiple_dependencies() {
        let service = OsvService::new();
        let deps = vec![
            dep("org.apache.logging.log4j:log4j-core", "2.14.1"),
            dep("com.google.guava:guava", "33.0.0-jre"),
            dep("junit:junit", "4.13.2"),
        ];

        let reports = service.check_dependencies(&deps).await.unwrap();
        assert_eq!(reports.len(), 3);
        assert_eq!(
            reports[0].dependency.name,
            "org.apache.logging.log4j:log4j-core"
        );
        assert_eq!(reports[1].dependency.name, "com.google.guava:guava");
        assert_eq!(reports[2].dependency.name, "junit:junit");
    }

    #[tokio::test]
    async fn check_dependency_without_version() {
        let service = OsvService::new();
        let deps = vec![dep("org.apache.logging.log4j:log4j-core", "")];

        let reports = service.check_dependencies(&deps).await.unwrap();
        assert_eq!(reports.len(), 1);
    }

    #[tokio::test]
    async fn report_contains_vulnerability_details() {
        let service = OsvService::new();
        let deps = vec![dep("org.apache.logging.log4j:log4j-core", "2.14.1")];

        let reports = service.check_dependencies(&deps).await.unwrap();
        let vuln = &reports[0].vulnerabilities[0];

        assert!(!vuln.id.is_empty(), "Vulnerability should have an ID");
        // Vulnerabilities always have an ID; summary/details/aliases may vary
        assert!(
            !vuln.summary.is_empty() || !vuln.details.is_empty() || !vuln.aliases.is_empty(),
            "Vulnerability should have a summary, details, or aliases"
        );
    }
}
