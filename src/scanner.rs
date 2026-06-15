use crate::hashing::hash_file_sha256;
use crate::ioc::IocEntry;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStatus {
    Clean,
    Match(String),
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub path: String,
    pub sha256: Option<String>,
    pub status: ScanStatus,
}

pub fn scan_target(target: &Path, iocs: &[IocEntry]) -> Vec<ScanResult> {
    let mut results = Vec::new();
    let mut paths_to_visit = vec![target.to_path_buf()];

    if !target.exists() {
        results.push(ScanResult {
            path: target.to_string_lossy().into_owned(),
            sha256: None,
            status: ScanStatus::Error("Target path does not exist".to_string()),
        });
        return results;
    }

    while let Some(current_path) = paths_to_visit.pop() {
        let metadata = match fs::metadata(&current_path) {
            Ok(meta) => meta,
            Err(e) => {
                results.push(ScanResult {
                    path: current_path.to_string_lossy().into_owned(),
                    sha256: None,
                    status: ScanStatus::Error(e.to_string()),
                });
                continue;
            }
        };

        if metadata.is_file() {
            let path_str = current_path.to_string_lossy().into_owned();
            match hash_file_sha256(&current_path) {
                Ok(hash) => {
                    if let Some(matched_ioc) = iocs.iter().find(|ioc| ioc.hash == hash) {
                        results.push(ScanResult {
                            path: path_str,
                            sha256: Some(hash),
                            status: ScanStatus::Match(matched_ioc.label.clone()),
                        });
                    } else {
                        results.push(ScanResult {
                            path: path_str,
                            sha256: Some(hash),
                            status: ScanStatus::Clean,
                        });
                    }
                }
                Err(e) => {
                    results.push(ScanResult {
                        path: path_str,
                        sha256: None,
                        status: ScanStatus::Error(e.to_string()),
                    });
                }
            }
        } else if metadata.is_dir() {
            match fs::read_dir(&current_path) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        paths_to_visit.push(entry.path());
                    }
                }
                Err(e) => {
                    results.push(ScanResult {
                        path: current_path.to_string_lossy().into_owned(),
                        sha256: None,
                        status: ScanStatus::Error(e.to_string()),
                    });
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_non_existent() {
        let target = Path::new("does_not_exist_file_12345");
        let results = scan_target(target, &[]);
        assert_eq!(results.len(), 1);
    }
}
