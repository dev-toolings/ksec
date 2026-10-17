use crate::policy::{Profile, Suppressed};
use crate::scanner::{ScanResult, Severity};
use colored::Colorize;

pub fn severity_color(s: &Severity) -> colored::ColoredString {
    match s {
        Severity::Info => "INFO".dimmed(),
        Severity::Low => "LOW".blue(),
        Severity::Medium => "MEDIUM".yellow(),
        Severity::High => "HIGH".red(),
        Severity::Critical => "CRITICAL".red().bold(),
    }
}

fn parse_min_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" | "med" => Severity::Medium,
        "high" => Severity::High,
        "critical" | "crit" => Severity::Critical,
        _ => Severity::Low,
    }
}

pub fn print_report(
    results: &[ScanResult],
    min_severity: &str,
    suppressed: Option<(Suppressed, Profile)>,
) {
    let min = parse_min_severity(min_severity);
    println!();
    println!("{}", "═══ ksec scan report ═══".bold());
    println!();

    let mut total_findings = 0;
    let mut high_or_above = 0;

    for result in results {
        let status = if result.findings.is_empty() {
            "PASS".green()
        } else {
            "WARN".red()
        };

        println!(
            "  {} {} [{}] ({}ms)",
            status,
            result.scanner.bold(),
            result.category,
            result.duration_ms
        );

        let filtered: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.severity >= min)
            .collect();

        for f in &filtered {
            let loc = match (&f.file, f.line) {
                (Some(file), Some(line)) => format!("{}:{}", file, line),
                (Some(file), None) => file.clone(),
                _ => String::new(),
            };

            println!(
                "       {} {} {}",
                severity_color(&f.severity),
                f.title,
                loc.dimmed()
            );

            if let Some(detail) = &f.detail {
                println!("              {}", detail.dimmed());
            }
        }

        total_findings += filtered.len();
        high_or_above += filtered
            .iter()
            .filter(|f| f.severity >= Severity::High)
            .count();

        if !filtered.is_empty() {
            println!();
        }
    }

    println!();
    println!("{}", "─── summary ───".dimmed());
    println!("  scanners: {} run", results.len().to_string().bold(),);
    println!(
        "  findings: {} total, {} high/critical",
        total_findings.to_string().bold(),
        if high_or_above > 0 {
            high_or_above.to_string().red().bold()
        } else {
            "0".green().bold()
        }
    );
    match suppressed {
        Some((s, profile)) => {
            let label = match profile {
                Profile::Dev => "dev",
                Profile::Strict => "strict",
            };
            println!(
                "  policy:   profile {}, {} suppressed ({} profile, {} allowlist, {} baseline){}",
                label.bold(),
                s.total(),
                s.profile,
                s.allow,
                s.baseline,
                if s.total() > 0 {
                    " -- --no-policy to show"
                } else {
                    ""
                }
            );
        }
        None => println!("  policy:   disabled (--no-policy)"),
    }
    println!();
}

pub fn print_json(results: &[ScanResult]) {
    let json = serde_json::to_string_pretty(results).unwrap_or_default();
    println!("{json}");
}

pub fn exit_code(results: &[ScanResult]) -> i32 {
    let has_high = results
        .iter()
        .any(|r| r.findings.iter().any(|f| f.severity >= Severity::High));
    if has_high { 1 } else { 0 }
}
