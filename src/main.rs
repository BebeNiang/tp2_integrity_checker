mod hashing;
mod ioc;
mod report;
mod scanner;

use scanner::ScanStatus;
use std::env;
use std::path::Path;

fn print_usage() {
    println!(
        "Usage:\n  tp2_integrity_checker --target <FILE_OR_DIRECTORY> --ioc <IOC_FILE> --report <REPORT_FILE> [--json] [--only-matches]"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut target_arg = None;
    let mut ioc_arg = None;
    let mut report_arg = None;
    let mut use_json = false;
    let mut only_matches = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                if i + 1 < args.len() {
                    target_arg = Some(&args[i + 1]);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--ioc" => {
                if i + 1 < args.len() {
                    ioc_arg = Some(&args[i + 1]);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--report" => {
                if i + 1 < args.len() {
                    report_arg = Some(&args[i + 1]);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--json" => {
                use_json = true;
                i += 1;
            }
            "--only-matches" => {
                only_matches = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    let (target_path, ioc_path, report_path) = match (target_arg, ioc_arg, report_arg) {
        (Some(t), Some(i), Some(r)) => (Path::new(t), Path::new(i), Path::new(r)),
        _ => {
            print_usage();
            std::process::exit(1);
        }
    };

    println!("TP2 File Integrity Checker (with Bonus Options)");

    let (iocs, invalid_ioc_lines) = match ioc::load_iocs(ioc_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("[ERROR] Failed to read IOC file: {}", e);
            std::process::exit(1);
        }
    };

    let mut scan_results = scanner::scan_target(target_path, &iocs);
    let mut files_scanned = 0;
    let mut matches_found = 0;
    let mut errors_count = 0;
    let mut matches = Vec::new();

    for res in &scan_results {
        match &res.status {
            ScanStatus::Clean => files_scanned += 1,
            ScanStatus::Match(_) => {
                files_scanned += 1;
                matches_found += 1;
                matches.push(res);
            }
            ScanStatus::Error(_) => errors_count += 1,
        }
    }

    println!(
        "Summary:\n  * Files scanned: {}\n  * IOC entries loaded: {}\n  * Invalid IOC lines: {}\n  * Matches found: {}\n  * Errors: {}",
        files_scanned,
        iocs.len(),
        invalid_ioc_lines,
        matches_found,
        errors_count
    );

    if !matches.is_empty() {
        println!("\nMatches:");
        for mat in &matches {
            println!("  [ALERT] {}", mat.path);
            if let Some(ref sha) = mat.sha256 {
                println!("    SHA-256: {}", sha);
            }
            if let ScanStatus::Match(ref label) = mat.status {
                println!("    IOC label: {}", label);
            }
        }
    }

    if only_matches {
        scan_results.retain(|res| matches!(res.status, ScanStatus::Match(_)));
    }

    let report_res = if use_json {
        report::write_json_report(report_path, &scan_results)
    } else {
        report::write_csv_report(report_path, &scan_results)
    };

    if let Err(e) = report_res {
        eprintln!("[ERROR] Failed to write report: {}", e);
    } else {
        println!("\nReport written successfully to {}", report_path.display());
    }
}
