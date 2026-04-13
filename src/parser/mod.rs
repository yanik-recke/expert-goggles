pub mod gradle;
pub mod maven;

use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
}

pub trait DependencyParser {
    fn parse(&self, content: &str) -> Result<Vec<Dependency>>;
}
