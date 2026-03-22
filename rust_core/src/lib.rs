use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::HashMap;
use threatdeflect_core::{AnalysisResult, SecretAnalyzer};

#[pyclass]
struct RustAnalyzer {
    inner: SecretAnalyzer,
}

#[pymethods]
impl RustAnalyzer {
    #[new]
    fn new(rules: HashMap<String, String>, suspicious_rules: HashMap<String, String>) -> PyResult<Self> {
        let inner = SecretAnalyzer::new(rules, suspicious_rules)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(RustAnalyzer { inner })
    }

    fn process_file_content<'py>(
        &self,
        py: Python<'py>,
        content: &str,
        file_path: &str,
        file_name: &str,
    ) -> PyResult<(Bound<'py, PyList>, Bound<'py, PyList>)> {
        let result = self.inner.analyze_content(content, file_path, file_name);
        Ok((
            findings_to_pylist(py, &result)?,
            iocs_to_pylist(py, &result)?,
        ))
    }
}

fn findings_to_pylist<'py>(py: Python<'py>, result: &AnalysisResult) -> PyResult<Bound<'py, PyList>> {
    let findings = PyList::empty(py);
    for f in &result.findings {
        let d = PyDict::new(py);
        d.set_item("description", &f.description)?;
        d.set_item("type", &f.finding_type)?;
        d.set_item("file", &f.file)?;
        d.set_item("match_content", &f.match_content)?;
        d.set_item("confidence", f.confidence)?;
        d.set_item("file_context", f.file_context.as_str())?;
        findings.append(d)?;
    }
    Ok(findings)
}

fn iocs_to_pylist<'py>(py: Python<'py>, result: &AnalysisResult) -> PyResult<Bound<'py, PyList>> {
    let iocs = PyList::empty(py);
    for i in &result.iocs {
        let d = PyDict::new(py);
        d.set_item("ioc", &i.ioc)?;
        d.set_item("source_file", &i.source_file)?;
        iocs.append(d)?;
    }
    Ok(iocs)
}

#[pymodule]
fn threatdeflect_rs(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RustAnalyzer>()?;
    Ok(())
}
