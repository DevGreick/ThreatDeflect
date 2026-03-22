use thiserror::Error;

/// Errors that can occur when constructing a [`SecretAnalyzer`](crate::SecretAnalyzer).
#[derive(Debug, Error)]
pub enum AnalyzerError {
    #[error("invalid regex pattern for rule '{rule_id}': {source}")]
    InvalidPattern {
        rule_id: String,
        source: regex::Error,
    },

    #[error("I/O error at '{path}': {source}")]
    IoError {
        path: String,
        source: std::io::Error,
    },
}
