use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Classification of a file's context within a repository.
///
/// Used to adjust confidence scores — findings in test files are
/// less likely to be real secrets than findings in production code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileContext {
    Production,
    Test,
    Example,
    Template,
    Documentation,
}

impl FileContext {
    /// Returns the confidence multiplier for this context.
    /// Production = 1.0, Test = 0.3, Example = 0.2, Template = 0.15, Docs = 0.2.
    pub fn multiplier(&self) -> f64 {
        match self {
            Self::Production => 1.0,
            Self::Test => 0.3,
            Self::Example => 0.2,
            Self::Template => 0.15,
            Self::Documentation => 0.2,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Production => "Production",
            Self::Test => "Test",
            Self::Example => "Example",
            Self::Template => "Template",
            Self::Documentation => "Documentation",
        }
    }
}

/// A single detection result from the analyzer.
///
/// Contains the matched content, its type (rule ID), a confidence score
/// between 0.0 and 1.0, and the file context where it was found.
///
/// Sensitive fields (`match_content`, `description`) are zeroed on drop
/// to prevent secrets from lingering in memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// Human-readable description of what was detected.
    pub description: String,
    /// Rule ID that triggered this finding (e.g. "AWS Key", "Reverse Shell").
    pub finding_type: String,
    /// File path where the finding was detected.
    pub file: String,
    /// The actual matched text from the source code.
    pub match_content: String,
    /// Confidence score between 0.0 (false positive) and 1.0 (confirmed secret).
    pub confidence: f64,
    /// File context classification (Production, Test, Example, etc.).
    pub file_context: FileContext,
}

impl Drop for Finding {
    fn drop(&mut self) {
        self.match_content.zeroize();
        self.description.zeroize();
    }
}

/// An Indicator of Compromise extracted from source code.
///
/// Typically a URL or IP address found in plaintext or decoded from base64.
/// The `ioc` field is zeroed on drop.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct Ioc {
    /// The extracted IOC value (URL, IP, domain).
    pub ioc: String,
    /// File path where the IOC was found.
    pub source_file: String,
}

impl Drop for Ioc {
    fn drop(&mut self) {
        self.ioc.zeroize();
    }
}

/// Combined results from analyzing a single file or multiple files.
///
/// Use [`merge`](Self::merge) to combine results from scanning multiple files.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisResult {
    /// All detected secrets, suspicious patterns, and high-entropy strings.
    pub findings: Vec<Finding>,
    /// All extracted Indicators of Compromise (URLs, IPs).
    pub iocs: Vec<Ioc>,
}

impl AnalysisResult {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            iocs: Vec::new(),
        }
    }

    /// Merges another result into this one, consuming the other.
    pub fn merge(&mut self, other: AnalysisResult) {
        self.findings.extend(other.findings);
        self.iocs.extend(other.iocs);
    }
}

impl Default for AnalysisResult {
    fn default() -> Self {
        Self::new()
    }
}
