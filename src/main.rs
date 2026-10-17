mod cli;
mod init;
mod lockfile;
mod policy;
mod report;
mod rules;
mod runner;
mod scanner;
mod scanners;
mod walk;

use clap::{CommandFactory, Parser};
use cli::{Cli, Commands};
use std::path::PathBuf;

fn resolve_path(path: &PathBuf) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.clone())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Init { force }) => {
            init::run_init(*force);
        }
        Some(Commands::Scan { path }) => {
            run_scan(scanners::all_scanners(), &resolve_path(path), &cli).await;
        }
        Some(Commands::Secrets { path }) => {
            run_scan(scanners::secrets_scanners(), &resolve_path(path), &cli).await;
        }
        Some(Commands::Deps { path }) => {
            run_scan(scanners::deps_scanners(), &resolve_path(path), &cli).await;
        }
        Some(Commands::Sast { path }) => {
            run_scan(scanners::sast_scanners(), &resolve_path(path), &cli).await;
        }
        Some(Commands::SupplyChain { path }) => {
            run_scan(scanners::supply_chain_scanners(), &resolve_path(path), &cli).await;
        }
        Some(Commands::Obfuscation { path }) => {
            run_scan(scanners::obfuscation_scanners(), &resolve_path(path), &cli).await;
        }
        Some(Commands::Baseline { path }) => {
            run_baseline(&resolve_path(path), &cli).await;
        }
        Some(Commands::Hash { file }) => match policy::file_sha256(file) {
            Some(sha) => println!("{sha}  {}", file.display()),
            None => {
                eprintln!("cannot read {}", file.display());
                std::process::exit(2);
            }
        },
        None => {
            Cli::command().print_help().ok();
            println!();
        }
    }
}

async fn run_scan(
    scan_list: Vec<std::sync::Arc<dyn scanner::Scanner>>,
    target: &std::path::Path,
    cli: &Cli,
) {
    let mut results = runner::run_scanners(scan_list, target).await;

    let suppressed = if cli.no_policy {
        None
    } else {
        let policy = load_policy(target, cli);
        Some((policy.apply(&mut results, target), policy.profile))
    };

    if cli.json {
        report::print_json(&results);
        if let Some((s, _)) = suppressed.filter(|(s, _)| s.total() > 0) {
            eprintln!(
                "ksec: {} findings suppressed ({} dev profile, {} allowlist, {} baseline)",
                s.total(),
                s.profile,
                s.allow,
                s.baseline
            );
        }
    } else {
        report::print_report(&results, &cli.min_severity, suppressed);
    }

    std::process::exit(report::exit_code(&results));
}

fn load_policy(target: &std::path::Path, cli: &Cli) -> policy::Policy {
    let flag = cli.profile.as_deref().and_then(policy::Profile::parse);
    let policy = policy::Policy::load(target, flag);
    for w in &policy.warnings {
        eprintln!("ksec: warning: {w}");
    }
    policy
}

async fn run_baseline(target: &std::path::Path, cli: &Cli) {
    let mut results = runner::run_scanners(scanners::all_scanners(), target).await;
    let policy = load_policy(target, cli);
    match policy.write_baseline(&mut results, target) {
        Ok((path, count, protected)) => {
            println!(
                "  baseline: {count} findings recorded in {}",
                path.display()
            );
            if protected > 0 {
                println!(
                    "  {protected} protected findings (obfuscation, critical supply-chain) were not baselined:"
                );
                println!(
                    "  review them, then validate each with an [[allow]] entry carrying its sha256 (`ksec hash <file>`)"
                );
            }
        }
        Err(e) => {
            eprintln!("ksec: cannot write baseline: {e}");
            std::process::exit(2);
        }
    }
}
