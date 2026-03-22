use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

use crate::error::AnalyzerError;

const DEFAULT_SKIP_DIRS: &[&str] = &[
    "node_modules", "vendor", "third_party", ".git", "__pycache__",
    "dist", "build", "target", ".tox", ".mypy_cache", ".pytest_cache",
    "venv", ".venv", "env", ".env", "site-packages",
];

const DEFAULT_SKIP_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "ico", "svg", "webp", "bmp",
    "woff", "woff2", "ttf", "eot", "otf",
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar",
    "exe", "dll", "so", "dylib", "o", "a",
    "pyc", "pyo", "class", "jar",
    "pdf", "doc", "docx", "xls", "xlsx",
    "mp3", "mp4", "avi", "mov", "wav",
    "lock", "sum",
];

const MAX_FILE_SIZE: u64 = 1_048_576; // 1MB

/// Walks a directory respecting `.gitignore`, `.ignore`, and built-in skip lists.
/// Returns a list of file paths suitable for scanning.
pub fn list_scannable_files(root: &Path) -> Result<Vec<PathBuf>, AnalyzerError> {
    if !root.is_dir() {
        return Err(AnalyzerError::IoError {
            path: root.to_string_lossy().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "directory not found"),
        });
    }

    let walker = WalkBuilder::new(root)
        .hidden(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .build();

    let skip_dirs: std::collections::HashSet<&str> = DEFAULT_SKIP_DIRS.iter().copied().collect();
    let skip_exts: std::collections::HashSet<&str> = DEFAULT_SKIP_EXTENSIONS.iter().copied().collect();

    let mut files = Vec::new();

    for entry in walker {
        let entry = entry.map_err(|e| AnalyzerError::IoError {
            path: root.to_string_lossy().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
        })?;

        let path = entry.path();

        if path.is_dir() {
            continue;
        }

        if let Some(parent) = path.parent() {
            let dominated = parent
                .components()
                .any(|c| skip_dirs.contains(c.as_os_str().to_str().unwrap_or("")));
            if dominated {
                continue;
            }
        }

        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if skip_exts.contains(ext.to_lowercase().as_str()) {
                continue;
            }
        }

        if let Ok(meta) = path.metadata() {
            if meta.len() > MAX_FILE_SIZE {
                continue;
            }
        }

        files.push(path.to_path_buf());
    }

    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_list_files_skips_binaries() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        fs::write(tmp.path().join("config.py"), "secret = 'test'").expect("write");
        fs::write(tmp.path().join("image.png"), &[0u8; 100]).expect("write");
        fs::write(tmp.path().join("archive.zip"), &[0u8; 100]).expect("write");

        let files = list_scannable_files(tmp.path()).expect("walk");
        let names: Vec<_> = files.iter().filter_map(|p| p.file_name()?.to_str()).collect();
        assert!(names.contains(&"config.py"));
        assert!(!names.contains(&"image.png"));
        assert!(!names.contains(&"archive.zip"));
    }

    #[test]
    fn test_list_files_skips_node_modules() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let nm = tmp.path().join("node_modules").join("pkg");
        fs::create_dir_all(&nm).expect("mkdir");
        fs::write(nm.join("index.js"), "module.exports = {}").expect("write");
        fs::write(tmp.path().join("app.js"), "const x = 1;").expect("write");

        let files = list_scannable_files(tmp.path()).expect("walk");
        let names: Vec<_> = files.iter().filter_map(|p| p.file_name()?.to_str()).collect();
        assert!(names.contains(&"app.js"));
        assert!(!names.contains(&"index.js"));
    }

    #[test]
    fn test_nonexistent_dir() {
        let result = list_scannable_files(Path::new("/nonexistent/path/abc123"));
        assert!(result.is_err());
    }
}
