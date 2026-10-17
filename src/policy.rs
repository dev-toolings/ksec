//! Ce qui doit passer sur un poste de dev, et ce qui ne passe jamais.
//!
//! Trois filtres s'appliquent après les scanners, dans cet ordre :
//!
//! 1. le profil `dev` (`--profile dev` ou `profile = "dev"` dans `.ksec.toml`)
//!    écarte ce qu'un poste de dev contient par construction : `.env.example`,
//!    base de données locale, identifiants de CI, fixtures, libellés i18n ;
//! 2. les entrées `[[allow]]` de `.ksec.toml`, chacune avec sa raison ;
//! 3. la baseline `.ksec-baseline.json` écrite par `ksec baseline`.
//!
//! L'obfuscation et les indicateurs de ver critiques sont protégés : ni le
//! profil ni la baseline ne les masquent, et une entrée `[[allow]]` ne le fait
//! que si elle porte le `sha256` exact du fichier. Un fichier validé qui change
//! d'un octet redevient une alerte.

use crate::scanner::{Category, Finding, ScanResult, Severity};
use globset::{Glob, GlobMatcher};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub const CONFIG_FILE: &str = ".ksec.toml";
pub const BASELINE_FILE: &str = ".ksec-baseline.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Strict,
    Dev,
}

impl Profile {
    pub fn parse(s: &str) -> Option<Profile> {
        match s.to_ascii_lowercase().as_str() {
            "strict" | "ci" => Some(Profile::Strict),
            "dev" => Some(Profile::Dev),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
struct ConfigFile {
    profile: Option<String>,
    #[serde(default)]
    allow: Vec<AllowRaw>,
}

#[derive(Deserialize)]
struct AllowRaw {
    rule: String,
    path: Option<String>,
    reason: Option<String>,
    sha256: Option<String>,
}

struct Allow {
    rule: String,
    path: Option<GlobMatcher>,
    sha256: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct BaselineFile {
    version: u32,
    fingerprints: Vec<String>,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct Suppressed {
    pub profile: usize,
    pub allow: usize,
    pub baseline: usize,
}

impl Suppressed {
    pub fn total(&self) -> usize {
        self.profile + self.allow + self.baseline
    }
}

pub struct Policy {
    pub profile: Profile,
    /// Répertoire de `.ksec.toml` (ou la cible s'il n'y en a pas) : les chemins
    /// `[[allow]]` et la baseline y sont relatifs.
    pub root: PathBuf,
    allows: Vec<Allow>,
    baseline: HashSet<String>,
    pub warnings: Vec<String>,
}

/// Cherche `.ksec.toml` dans la cible puis en remontant : un seul fichier dans
/// `~/lab` couvre tous les projets qu'il contient.
fn find_config(target: &Path) -> Option<PathBuf> {
    let start = if target.is_dir() {
        target
    } else {
        target.parent()?
    };
    start
        .ancestors()
        .map(|d| d.join(CONFIG_FILE))
        .find(|p| p.is_file())
}

impl Policy {
    /// `profile_flag` l'emporte sur le fichier. Sans l'un ni l'autre : strict.
    pub fn load(target: &Path, profile_flag: Option<Profile>) -> Policy {
        let mut warnings = Vec::new();
        let config_path = find_config(target);
        let root = config_path
            .as_ref()
            .and_then(|p| p.parent())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| target.to_path_buf());

        let mut file_profile = None;
        let mut allows = Vec::new();
        if let Some(path) = &config_path {
            match fs::read_to_string(path).map(|c| toml::from_str::<ConfigFile>(&c)) {
                Ok(Ok(cfg)) => {
                    if let Some(p) = cfg.profile.as_deref() {
                        file_profile = Profile::parse(p);
                        if file_profile.is_none() {
                            warnings.push(format!("{}: unknown profile {p:?}", path.display()));
                        }
                    }
                    for (i, raw) in cfg.allow.into_iter().enumerate() {
                        let n = i + 1;
                        if raw.reason.as_deref().is_none_or(|r| r.trim().is_empty()) {
                            warnings.push(format!(
                                "{}: [[allow]] #{n} ({}) ignored, `reason` is required",
                                path.display(),
                                raw.rule
                            ));
                            continue;
                        }
                        let matcher = match raw.path.as_deref().map(Glob::new) {
                            None => None,
                            Some(Ok(g)) => Some(g.compile_matcher()),
                            Some(Err(e)) => {
                                warnings.push(format!(
                                    "{}: [[allow]] #{n} bad path glob: {e}",
                                    path.display()
                                ));
                                continue;
                            }
                        };
                        allows.push(Allow {
                            rule: raw.rule,
                            path: matcher,
                            sha256: raw.sha256.map(|s| s.to_ascii_lowercase()),
                        });
                    }
                }
                Ok(Err(e)) => warnings.push(format!("{}: {e}", path.display())),
                Err(e) => warnings.push(format!("{}: {e}", path.display())),
            }
        }

        let baseline = fs::read_to_string(root.join(BASELINE_FILE))
            .ok()
            .and_then(|c| serde_json::from_str::<BaselineFile>(&c).ok())
            .map(|b| b.fingerprints.into_iter().collect())
            .unwrap_or_default();

        Policy {
            profile: profile_flag.or(file_profile).unwrap_or(Profile::Strict),
            root,
            allows,
            baseline,
            warnings,
        }
    }

    /// Filtre `results` en place et compte ce qui a été écarté.
    pub fn apply(&self, results: &mut [ScanResult], target: &Path) -> Suppressed {
        self.apply_inner(results, target, true)
    }

    fn apply_inner(
        &self,
        results: &mut [ScanResult],
        target: &Path,
        use_baseline: bool,
    ) -> Suppressed {
        let mut sup = Suppressed::default();
        let mut files = FileCache::default();
        for result in results.iter_mut() {
            result.findings.retain(|f| {
                let Some(ctx) = FindingCtx::new(f, target, &self.root, &mut files) else {
                    return true;
                };
                let protected = is_protected(f);
                if !protected && self.profile == Profile::Dev && dev_profile_allows(f, &ctx) {
                    sup.profile += 1;
                    return false;
                }
                if self.allows.iter().any(|a| a.matches(f, &ctx, protected)) {
                    sup.allow += 1;
                    return false;
                }
                if use_baseline && !protected && self.baseline.contains(&ctx.fingerprint(f)) {
                    sup.baseline += 1;
                    return false;
                }
                true
            });
        }
        sup
    }

    /// Écrit la baseline de ce qui reste après profil et allowlist. Les
    /// alertes protégées n'y entrent pas : elles se valident une à une.
    pub fn write_baseline(
        &self,
        results: &mut [ScanResult],
        target: &Path,
    ) -> std::io::Result<(PathBuf, usize, usize)> {
        self.apply_inner(results, target, false);
        let mut files = FileCache::default();
        let mut fingerprints = Vec::new();
        let mut protected = 0;
        for f in results.iter().flat_map(|r| r.findings.iter()) {
            if is_protected(f) {
                protected += 1;
                continue;
            }
            if let Some(ctx) = FindingCtx::new(f, target, &self.root, &mut files) {
                fingerprints.push(ctx.fingerprint(f));
            }
        }
        fingerprints.sort();
        fingerprints.dedup();
        let path = self.root.join(BASELINE_FILE);
        let body = serde_json::to_string_pretty(&BaselineFile {
            version: 1,
            fingerprints: fingerprints.clone(),
        })?;
        fs::write(&path, body + "\n")?;
        Ok((path, fingerprints.len(), protected))
    }
}

pub fn is_protected(f: &Finding) -> bool {
    f.category == Category::Obfuscation
        || (f.category == Category::SupplyChain && f.severity == Severity::Critical)
}

/// Identifiant de règle : la dernière parenthèse du titre, `(db-uri-password)`.
pub fn rule_id(title: &str) -> &str {
    title
        .rfind('(')
        .filter(|_| title.ends_with(')'))
        .map(|i| &title[i + 1..title.len() - 1])
        .unwrap_or(title)
}

impl Allow {
    fn matches(&self, f: &Finding, ctx: &FindingCtx, protected: bool) -> bool {
        let rule_ok =
            self.rule == "*" || rule_id(&f.title) == self.rule || f.title.contains(&self.rule);
        if !rule_ok {
            return false;
        }
        if let Some(m) = &self.path
            && !m.is_match(&ctx.root_rel)
        {
            return false;
        }
        match (&self.sha256, protected) {
            (Some(want), _) => ctx.sha256.as_deref() == Some(want.as_str()),
            (None, true) => false,
            (None, false) => true,
        }
    }
}

#[derive(Default)]
struct FileCache {
    files: HashMap<PathBuf, Option<(String, String)>>,
}

impl FileCache {
    /// (contenu, sha256) d'un fichier, lu une seule fois quel que soit le
    /// nombre d'alertes qu'il porte.
    fn get(&mut self, path: &Path) -> Option<&(String, String)> {
        self.files
            .entry(path.to_path_buf())
            .or_insert_with(|| {
                let bytes = fs::read(path).ok()?;
                let sha = hex(&Sha256::digest(&bytes));
                Some((String::from_utf8_lossy(&bytes).into_owned(), sha))
            })
            .as_ref()
    }
}

struct FindingCtx {
    /// Chemin relatif à la racine de la politique, séparateurs `/`.
    root_rel: String,
    line_text: String,
    sha256: Option<String>,
}

impl FindingCtx {
    fn new(f: &Finding, target: &Path, root: &Path, files: &mut FileCache) -> Option<FindingCtx> {
        let file = f.file.as_ref()?;
        let abs = target.join(file);
        let root_rel = abs
            .strip_prefix(root)
            .unwrap_or(Path::new(file))
            .to_string_lossy()
            .replace('\\', "/");
        let (line_text, sha256) = match files.get(&abs) {
            Some((content, sha)) => {
                let line = f
                    .line
                    .and_then(|n| content.lines().nth(n.saturating_sub(1) as usize))
                    .unwrap_or("")
                    .trim()
                    .to_string();
                (line, Some(sha.clone()))
            }
            None => (String::new(), None),
        };
        Some(FindingCtx {
            root_rel,
            line_text,
            sha256,
        })
    }

    /// Stable tant que la ligne fautive ne change pas, même si elle se déplace.
    fn fingerprint(&self, f: &Finding) -> String {
        let mut h = Sha256::new();
        for part in [
            f.scanner.as_str(),
            rule_id(&f.title),
            &self.root_rel,
            &self.line_text,
        ] {
            h.update(part.as_bytes());
            h.update([0]);
        }
        hex(&h.finalize())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn file_sha256(path: &Path) -> Option<String> {
    fs::read(path).ok().map(|b| hex(&Sha256::digest(&b)))
}

// ── Profil dev ────────────────────────────────────────────────────────────────

/// Hôte de base de données qui ne quitte pas la machine : boucle locale, les
/// services `infra-*` partagés, ou un nom de service docker compose.
static LOCAL_DB_HOST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal|infra-[\w-]+|postgres(?:ql)?|mysql|mariadb|db|database|redis|mongo(?:db)?|rabbitmq)(?::\d+)?(?:[/?"'\s`]|$)"#,
    )
    .unwrap()
});

static QUOTED_VALUE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[:=]\s*["'`]([^"'`]*)["'`]"#).unwrap());

static MOCK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b\w*(?:mock|fake|dummy|sample|stub)\w*\b").unwrap());

/// Identifiant qui annonce une valeur de dev : `DEV_SEED_PASSWORD`,
/// `DEMO_PASSWORD`, `const DEV_ADMIN = { ... }`.
static DEV_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b\w*(?:^|_|\b)(?:dev|demo|seed|sample|samples|test|local|e2e)(?:_|\b)\w*\s*[:=]",
    )
    .unwrap()
});

const DEV_VALUES: &[&str] = &[
    "",
    "password",
    "postgres",
    "secret",
    "changeme",
    "admin",
    "root",
    "test",
    "dev",
    "local",
    "example",
    "demo",
    "pass",
    "passw0rd",
    "123456",
    "12345678",
    "password123",
    "mysql",
    "redis",
    "guest",
    "user",
    "toor",
    "minioadmin",
];
const DEV_VALUE_PREFIXES: &[&str] = &[
    "@generate",
    "dev-",
    "dev_",
    "local-",
    "local_",
    "test-",
    "test_",
    "fake",
    "dummy",
    "sample",
];

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn is_env_template(path: &str) -> bool {
    let name = file_name(path).to_ascii_lowercase();
    [".example", ".sample", ".template", ".dist", ".tpl"]
        .iter()
        .any(|s| name.ends_with(s) || name.contains(&format!("{s}.")))
}

fn is_ci_file(path: &str) -> bool {
    path.contains(".github/workflows/")
        || path.ends_with(".gitlab-ci.yml")
        || path.contains("/.circleci/")
        || path.contains("/module-ci/")
}

fn is_test_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [
        "/test/",
        "/tests/",
        "/__tests__/",
        "/e2e/",
        "/fixtures/",
        "/fixture/",
        "/mocks/",
        "/__mocks__/",
        "/seeds/",
        "/seed/",
    ]
    .iter()
    .any(|s| p.contains(s))
        || [".test.", ".spec.", "_test.", "/seed.", "/seeds."]
            .iter()
            .any(|s| p.contains(s))
        || file_name(&p).starts_with("verify-")
        || file_name(&p).starts_with("samples.")
}

fn is_i18n_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [
        "/locales/",
        "/locale/",
        "/i18n/",
        "/lang/",
        "/translations/",
        "/messages/",
    ]
    .iter()
    .any(|s| p.contains(s))
        || file_name(&p).starts_with("messages.")
}

fn dev_value(line: &str) -> bool {
    QUOTED_VALUE_RE.captures_iter(line).any(|c| {
        let v = c[1].trim().to_ascii_lowercase();
        DEV_VALUES.contains(&v.as_str()) || DEV_VALUE_PREFIXES.iter().any(|p| v.starts_with(p))
    })
}

fn dev_profile_allows(f: &Finding, ctx: &FindingCtx) -> bool {
    let path = ctx.root_rel.as_str();
    let rule = rule_id(&f.title);
    let line = ctx.line_text.as_str();
    match f.category {
        Category::Secrets => {
            if is_env_template(path) || is_test_path(path) {
                return true;
            }
            match rule {
                "db-uri-password" => LOCAL_DB_HOST_RE.is_match(line) || is_ci_file(path),
                "password-assignment" => {
                    is_i18n_path(path)
                        || is_ci_file(path)
                        || dev_value(line)
                        || MOCK_RE.is_match(line)
                        || DEV_NAME_RE.is_match(line)
                }
                "private-key-generic" => {
                    let name = file_name(path).to_ascii_lowercase();
                    [
                        "dev",
                        "local",
                        "test",
                        "snakeoil",
                        "self-signed",
                        "selfsigned",
                    ]
                    .iter()
                    .any(|k| name.contains(k))
                }
                _ => MOCK_RE.is_match(line),
            }
        }
        // Le scanner supply-chain ne lit que le code du projet, pas les
        // dépendances : qu'une app appelle `fetch` ou ouvre un WebSocket, c'est
        // son métier.
        Category::SupplyChain => {
            f.severity <= Severity::Medium && matches!(rule, "http-request" | "websocket")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(category: Category, severity: Severity, title: &str, file: &str) -> Finding {
        Finding {
            severity,
            category,
            scanner: category.to_string(),
            title: title.into(),
            file: Some(file.into()),
            line: Some(1),
            detail: None,
        }
    }

    fn ctx(path: &str, line: &str) -> FindingCtx {
        FindingCtx {
            root_rel: path.into(),
            line_text: line.into(),
            sha256: Some("ab".repeat(32)),
        }
    }

    #[test]
    fn dev_profile_accepts_local_database_and_rejects_remote_one() {
        let f = finding(
            Category::Secrets,
            Severity::Critical,
            "Database URI with Password (db-uri-password)",
            "apps/api/src/env.ts",
        );
        assert!(dev_profile_allows(
            &f,
            &ctx(
                "apps/api/src/env.ts",
                r#"url: "postgres://app:app@localhost:5432/app","#
            )
        ));
        assert!(dev_profile_allows(
            &f,
            &ctx(
                "apps/api/src/env.ts",
                r#"DATABASE_URL="postgresql://u:p@infra-postgres:5432/x""#
            )
        ));
        assert!(!dev_profile_allows(
            &f,
            &ctx(
                "apps/api/src/env.ts",
                r#"url: "postgres://app:S3cr3t@db.prod.example.net/app""#
            )
        ));
    }

    #[test]
    fn dev_profile_accepts_placeholders_but_not_real_looking_passwords() {
        let f = finding(
            Category::Secrets,
            Severity::High,
            "Hardcoded Password (password-assignment)",
            "src/app/login.tsx",
        );
        assert!(dev_profile_allows(
            &f,
            &ctx("src/i18n/messages.fr.ts", r#"password: "Mot de passe","#)
        ));
        assert!(dev_profile_allows(
            &f,
            &ctx("scripts/setup.sh", r#"PASSWORD="changeme""#)
        ));
        assert!(!dev_profile_allows(
            &f,
            &ctx("src/app/login.tsx", r#"password: "Xk2!pq9Lm","#)
        ));
        assert!(dev_profile_allows(
            &f,
            &ctx(
                "src/app/login.tsx",
                r#"const DEV_SEED_PASSWORD = "Xk2!pq9Lm""#
            )
        ));
        assert!(!dev_profile_allows(
            &f,
            &ctx("src/app/login.tsx", r#"devicePassword: "Xk2!pq9Lm","#)
        ));
    }

    #[test]
    fn obfuscation_is_protected_from_profile_and_needs_exact_hash() {
        let f = finding(
            Category::Obfuscation,
            Severity::Critical,
            "x (obfuscator-io)",
            "node_modules/a/index.js",
        );
        assert!(is_protected(&f));
        let c = ctx("node_modules/a/index.js", "");
        let by_path = Allow {
            rule: "obfuscator-io".into(),
            path: None,
            sha256: None,
        };
        assert!(!by_path.matches(&f, &c, true));
        let by_hash = Allow {
            rule: "obfuscator-io".into(),
            path: None,
            sha256: Some("ab".repeat(32)),
        };
        assert!(by_hash.matches(&f, &c, true));
        let stale = Allow {
            rule: "obfuscator-io".into(),
            path: None,
            sha256: Some("cd".repeat(32)),
        };
        assert!(!stale.matches(&f, &c, true));
    }

    #[test]
    fn allow_without_reason_is_rejected() {
        let dir = std::env::temp_dir().join(format!("ksec-policy-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(CONFIG_FILE),
            "profile = \"dev\"\n[[allow]]\nrule = \"*\"\n",
        )
        .unwrap();
        let p = Policy::load(&dir, None);
        assert_eq!(p.profile, Profile::Dev);
        assert!(p.allows.is_empty());
        assert_eq!(p.warnings.len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fingerprint_survives_a_line_move_but_not_a_content_change() {
        let mut f = finding(
            Category::Secrets,
            Severity::High,
            "Hardcoded Password (password-assignment)",
            "a.ts",
        );
        let a = ctx("a.ts", "password: 'Xk2'").fingerprint(&f);
        f.line = Some(40);
        assert_eq!(a, ctx("a.ts", "password: 'Xk2'").fingerprint(&f));
        assert_ne!(a, ctx("a.ts", "password: 'Yk3'").fingerprint(&f));
    }
}
