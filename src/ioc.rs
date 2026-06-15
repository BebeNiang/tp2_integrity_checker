use crate::hashing::is_valid_sha256;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocEntry {
    pub hash: String,
    pub label: String,
}

pub fn load_iocs(path: &Path) -> Result<(Vec<IocEntry>, usize), io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut entries = Vec::new();
    let mut invalid_count = 0;

    for line_result in reader.lines() {
        let line = line_result?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((hash, label)) = trimmed.split_once(',') {
            let hash_clean = hash.trim().to_lowercase();
            if is_valid_sha256(&hash_clean) {
                entries.push(IocEntry {
                    hash: hash_clean,
                    label: label.trim().to_string(),
                });
            } else {
                invalid_count += 1;
            }
        } else {
            invalid_count += 1;
        }
    }

    Ok((entries, invalid_count))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_is_valid_sha256_indirect() {
        assert!(crate::hashing::is_valid_sha256(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }
}
