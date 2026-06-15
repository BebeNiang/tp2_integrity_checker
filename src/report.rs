use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use crate::scanner::{ScanResult, ScanStatus};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv_report_creation() {
        let dummy_path = Path::new("reports/test_dummy.csv");
        let sample_results = vec![ScanResult {
            path: "test.txt".to_string(),
            sha256: Some("1234".to_string()),
            status: ScanStatus::Clean,
        }];
        let res = write_csv_report(dummy_path, &sample_results);
        assert!(res.is_ok());
        let _ = std::fs::remove_file(dummy_path);
    }
}
