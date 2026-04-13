use anyhow::{Context, Result};
use log::debug;
use roxmltree::Document;

use super::{Dependency, DependencyParser};

pub struct MavenParser;

impl DependencyParser for MavenParser {
    fn parse(&self, content: &str) -> Result<Vec<Dependency>> {
        let doc = Document::parse(content).context("Failed to parse pom.xml as XML")?;

        let mut deps = Vec::new();

        for node in doc.descendants() {
            if node.has_tag_name("dependency") {
                let group_id = node
                    .children()
                    .find(|n| n.has_tag_name("groupId"))
                    .and_then(|n| n.text())
                    .unwrap_or_default();

                let artifact_id = node
                    .children()
                    .find(|n| n.has_tag_name("artifactId"))
                    .and_then(|n| n.text())
                    .unwrap_or_default();

                let version = node
                    .children()
                    .find(|n| n.has_tag_name("version"))
                    .and_then(|n| n.text())
                    .unwrap_or_default()
                    .to_string();

                if !group_id.is_empty() && !artifact_id.is_empty() {
                    debug!("Found Maven dependency: {}:{} version {}", group_id, artifact_id, version);
                    deps.push(Dependency {
                        name: format!("{}:{}", group_id, artifact_id),
                        version,
                        ecosystem: "Maven".to_string(),
                    });
                }
            }
        }

        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_pom() {
        let pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.20</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
  </dependencies>
</project>"#;

        let deps = MavenParser.parse(pom).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "org.springframework:spring-core");
        assert_eq!(deps[0].version, "5.3.20");
        assert_eq!(deps[0].ecosystem, "Maven");
        assert_eq!(deps[1].name, "com.google.guava:guava");
        assert_eq!(deps[1].version, "31.1-jre");
    }

    #[test]
    fn parse_pom_with_namespace() {
        let pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
    </dependency>
  </dependencies>
</project>"#;

        let deps = MavenParser.parse(pom).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "junit:junit");
        assert_eq!(deps[0].version, "4.13.2");
    }

    #[test]
    fn parse_pom_missing_version() {
        let pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
    </dependency>
  </dependencies>
</project>"#;

        let deps = MavenParser.parse(pom).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "org.slf4j:slf4j-api");
        assert_eq!(deps[0].version, "");
    }

    #[test]
    fn parse_pom_no_dependencies() {
        let pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
</project>"#;

        let deps = MavenParser.parse(pom).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn parse_invalid_xml() {
        let result = MavenParser.parse("not xml at all");
        assert!(result.is_err());
    }
}
