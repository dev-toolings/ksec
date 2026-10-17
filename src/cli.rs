use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ksec",
    version,
    about = "Self-contained security scanner — secrets, deps, supply chain, SAST, obfuscation"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Target directory to scan (defaults to current directory)
    #[arg(global = true, default_value = ".")]
    pub path: PathBuf,

    /// Output as JSON
    #[arg(long, global = true)]
    pub json: bool,

    /// Only show findings at or above this severity
    #[arg(long, global = true, default_value = "low")]
    pub min_severity: String,

    /// Policy profile: `dev` lets through what a dev machine holds by design
    /// (.env.example, local databases, CI credentials, fixtures). Obfuscation
    /// is never hidden. Overrides `profile` in .ksec.toml
    #[arg(long, global = true, value_parser = ["strict", "dev"])]
    pub profile: Option<String>,

    /// Ignore .ksec.toml, the dev profile and the baseline: show everything
    #[arg(long, global = true)]
    pub no_policy: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run all scanners (secrets + deps + supply-chain + sast + obfuscation)
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Detect leaked secrets (150+ regex rules — API keys, tokens, private keys, DB URIs)
    Secrets {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Check dependencies for known vulnerabilities (parses lockfiles, queries OSV API)
    Deps {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Static analysis — OWASP Top 10 (SQLi, XSS, command injection, SSRF, etc.)
    Sast {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Detect suspicious patterns in packages (eval, network exfil, obfuscation, malicious scripts)
    SupplyChain {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Detect obfuscated payloads in code and installed dependencies (GlassWorm invisible
    /// Unicode, obfuscator.io, decode+exec loaders, .pth, Trojan Source)
    Obfuscation {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Record current findings in .ksec-baseline.json so later scans only show new ones
    /// (obfuscation and critical supply-chain findings are never baselined)
    Baseline {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Print the sha256 to put in an [[allow]] entry that validates a protected finding
    Hash { file: PathBuf },
    /// Generate lefthook.yml for pre-commit hooks
    Init {
        /// Overwrite existing lefthook.yml
        #[arg(long)]
        force: bool,
    },
}
