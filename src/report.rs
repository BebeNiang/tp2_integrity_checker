use crate::scanner::{ScanResult, ScanStatus};
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

pub fn write_csv_report(path: &Path, results: &[ScanResult]) -> Result<(), io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    writeln!(file, "path,sha256,status,label")?;
    for res in results {
        let sha = res.sha256.as_deref().unwrap_or("");
        match &res.status {
            ScanStatus::Clean => {
                writeln!(file, "{},{},CLEAN,", res.path, sha)?;
            }
            ScanStatus::Match(label) => {
                writeln!(file, "{},{},MATCH,{}", res.path, sha, label)?;
            }
            ScanStatus::Error(err) => {
                writeln!(file, "{},{},ERROR,{}", res.path, sha, err)?;
            }
        }
    }
    Ok(())
}

pub fn write_json_report(path: &Path, results: &[ScanResult]) -> Result<(), io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    writeln!(file, "[")?;
    for (i, res) in results.iter().enumerate() {
        let sha = res.sha256.as_deref().unwrap_or("");
        let (status_str, label_str) = match &res.status {
            ScanStatus::Clean => ("CLEAN", ""),
            ScanStatus::Match(label) => ("MATCH", label.as_str()),
            ScanStatus::Error(err) => ("ERROR", err.as_str()),
        };
        write!(
            file,
            "  {{\n    \"path\": \"{}\",\n    \"sha256\": \"{}\",\n    \"status\": \"{}\",\n    \"label\": \"{}\"\n  }}",
            res.path.replace('\\', "\\\\"),
            sha,
            status_str,
            label_str
        )?;
        if i < results.len() - 1 {
            writeln!(file, ",")?;
        } else {
            writeln!(file)?;
        }
    }
    writeln!(file, "]")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_csv_report_creation() {
        let dummy = Path::new("reports/test_dummy.csv");
        assert!(write_csv_report(dummy, &[]).is_ok());
        let _ = std::fs::remove_file(dummy);
    }
    #[test]
    fn test_json_report_creation() {
        let dummy = Path::new("reports/test_dummy.json");
        assert!(write_json_report(dummy, &[]).is_ok());
        let _ = std::fs::remove_file(dummy);
    }
}
