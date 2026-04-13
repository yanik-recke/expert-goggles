use anyhow::Result;
use log::debug;
use regex::Regex;

use super::{Dependency, DependencyParser};

pub struct GradleParser;

impl DependencyParser for GradleParser {
    fn parse(&self, content: &str) -> Result<Vec<Dependency>> {
        let mut deps = Vec::new();

        // Matches both Groovy DSL:  implementation 'group:name:version'
        // and Kotlin DSL:           implementation("group:name:version")
        let re = Regex::new(
            r#"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|classpath)\s*[('"]['"]?([^:'"]+):([^:'"]+):([^'")\s]+)['"]?[)'"]"#,
        )?;

        for cap in re.captures_iter(content) {
            debug!("Found Gradle dependency: {}:{} version {}", &cap[1], &cap[2], &cap[3]);
            deps.push(Dependency {
                name: format!("{}:{}", &cap[1], &cap[2]),
                version: cap[3].to_string(),
                ecosystem: "Maven".to_string(),
            });
        }

        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_groovy_single_quotes() {
        let gradle = r#"
dependencies {
    implementation 'com.google.guava:guava:31.1-jre'
    testImplementation 'junit:junit:4.13.2'
}
"#;

        let deps = GradleParser.parse(gradle).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "com.google.guava:guava");
        assert_eq!(deps[0].version, "31.1-jre");
        assert_eq!(deps[0].ecosystem, "Maven");
        assert_eq!(deps[1].name, "junit:junit");
        assert_eq!(deps[1].version, "4.13.2");
    }

    #[test]
    fn parse_groovy_double_quotes() {
        let gradle = r#"
dependencies {
    implementation "org.springframework:spring-core:5.3.20"
    runtimeOnly "org.postgresql:postgresql:42.5.0"
}
"#;

        let deps = GradleParser.parse(gradle).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "org.springframework:spring-core");
        assert_eq!(deps[0].version, "5.3.20");
        assert_eq!(deps[1].name, "org.postgresql:postgresql");
        assert_eq!(deps[1].version, "42.5.0");
    }

    #[test]
    fn parse_kotlin_dsl() {
        let gradle = r#"
dependencies {
    implementation("com.google.guava:guava:31.1-jre")
    api("org.apache.commons:commons-lang3:3.12.0")
}
"#;

        let deps = GradleParser.parse(gradle).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "com.google.guava:guava");
        assert_eq!(deps[0].version, "31.1-jre");
        assert_eq!(deps[1].name, "org.apache.commons:commons-lang3");
        assert_eq!(deps[1].version, "3.12.0");
    }

    #[test]
    fn parse_multiple_configurations() {
        let gradle = r#"
dependencies {
    implementation 'com.example:lib-a:1.0'
    api 'com.example:lib-b:2.0'
    compileOnly 'com.example:lib-c:3.0'
    runtimeOnly 'com.example:lib-d:4.0'
    testRuntimeOnly 'com.example:lib-e:5.0'
    classpath 'com.example:lib-f:6.0'
}
"#;

        let deps = GradleParser.parse(gradle).unwrap();
        assert_eq!(deps.len(), 6);
    }

    #[test]
    fn parse_no_dependencies() {
        let gradle = r#"
plugins {
    id 'java'
}
"#;

        let deps = GradleParser.parse(gradle).unwrap();
        assert!(deps.is_empty());
    }
}
