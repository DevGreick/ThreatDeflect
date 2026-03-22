//! # threatdeflect-core
//!
//! High-performance secret detection, confidence scoring, and IOC extraction engine.
//!
//! ## Overview
//!
//! This crate provides a configurable analyzer that scans source code for:
//! - Leaked credentials (AWS keys, GitHub tokens, API keys, etc.)
//! - Suspicious commands (reverse shells, crypto miners, encoded payloads)
//! - Indicators of Compromise (URLs/IPs, including base64-encoded)
//!
//! Each finding includes a **confidence score** (0.0–1.0) based on Shannon entropy,
//! file context (test/production/example), placeholder detection, and assignment patterns.
//!
//! ## Quick start
//!
//! ```rust
//! use threatdeflect_core::SecretAnalyzer;
//!
//! let rules = vec![
//!     ("AWS Key".to_string(), r"AKIA[0-9A-Z]{16}".to_string()),
//! ];
//! let analyzer = SecretAnalyzer::new(rules, Vec::<(String, String)>::new()).unwrap();
//! let result = analyzer.analyze_content("key = AKIAIOSFODNN7EXAMPLE1", "config.py", "config.py");
//! assert!(!result.findings.is_empty());
//! ```

pub mod analyzer;
pub mod confidence;
pub mod context;
pub mod error;
pub mod types;
pub mod walker;

pub use analyzer::SecretAnalyzer;
pub use error::AnalyzerError;
pub use types::{AnalysisResult, FileContext, Finding, Ioc};
pub use walker::list_scannable_files;
