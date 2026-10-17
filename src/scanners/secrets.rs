use crate::rules::secrets::secret_rules;
use crate::scanner::{Category, Finding, Scanner};
use crate::walk;
use std::fs;
use std::path::Path;

pub struct SecretsScanner;

const ALLOWLIST_PATTERNS: &[&str] = &[
    "EXAMPLE",
    "example",
    "PLACEHOLDER",
    "placeholder",
    "your-",
    "YOUR_",
    "xxx",
    "XXX",
    "000000",
    "CHANGE_ME",
    "change_me",
    "TODO",
    "FIXME",
    "<your",
    "${",
    "{{",
    "process.env",
    "os.environ",
    "os.getenv",
    "env(",
    "ENV[",
    "getenv(",
    "env::",
    "std::env",
    "env.Get",
    "config.",
    "Config.",
];

const SKIP_FILES: &[&str] = &[
    "package-lock.json",
    "bun.lock",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "composer.lock",
    "poetry.lock",
    "go.sum",
    "go.mod",
    ".gitignore",
    ".dockerignore",
    "LICENSE",
    "CHANGELOG.md",
];

const SKIP_EXTENSIONS: &[&str] = &[
    "md",
    "mdx",
    "txt",
    "rst",
    "adoc",
    "log",
    "min.js",
    "map",
    "snap",
    "test.js.snap",
    "jsonl",
];

const SKIP_PATH_SEGMENTS: &[&str] = &[
    "test",
    "tests",
    "spec",
    "specs",
    "__tests__",
    "__mocks__",
    "__fixtures__",
    "fixtures",
    "testdata",
    "test-data",
    "examples",
    "example",
    "demo",
    "demos",
    "docs",
    "documentation",
    "migrations",
];

fn is_test_or_fixture(path: &str) -> bool {
    let lower = path.to_lowercase();
    SKIP_PATH_SEGMENTS
        .iter()
        .any(|seg| lower.contains(&format!("/{seg}/")) || lower.starts_with(&format!("{seg}/")))
        || lower.ends_with(".test.ts")
        || lower.ends_with(".test.js")
        || lower.ends_with(".spec.ts")
        || lower.ends_with(".spec.js")
        || lower.ends_with("_test.go")
        || lower.ends_with("_test.py")
}

fn is_allowlisted(line: &str) -> bool {
    let trimmed = line.trim_start();

    if trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("<!--")
    {
        return true;
    }

    if line.contains("r#\"")
        || line.contains("r\"")
        || line.contains("Regex::new")
        || line.contains("regex!")
        || line.contains("re.compile")
        || line.contains("Pattern.compile")
        || line.contains("preg_match")
    {
        return true;
    }

    if line.contains("assert")
        || line.contains("expect(")
        || line.contains("test(")
        || line.contains("it(")
        || line.contains("describe(")
    {
        return true;
    }

    // Form field labels / HTML attributes (not real passwords)
    if line.contains("type=\"password\"")
        || line.contains("type='password'")
        || line.contains("type={\"password\"}")
        || line.contains("name=\"password\"")
        || line.contains("name='password'")
        || line.contains("placeholder=")
        || line.contains("autoComplete=")
        || line.contains("autocomplete=")
        || line.contains("label=")
        || line.contains("Label>")
        || line.contains("aria-label")
        || line.contains("htmlFor=")
    {
        return true;
    }

    // Validation schemas (zod, yup, joi)
    if line.contains(".min(")
        || line.contains(".max(")
        || line.contains(".regex(")
        || line.contains("z.string()")
        || line.contains("z.object(")
        || line.contains("Yup.")
        || line.contains("Joi.")
    {
        return true;
    }

    ALLOWLIST_PATTERNS.iter().any(|p| line.contains(p))
}

/// Valeur qui désigne un secret au lieu de le contenir : variable shell
/// (`"$DB_PASSWORD"`, `"$(openssl rand -hex 32)"`), paramètre Symfony
/// (`'%app.secret%'`), nom de variable d'environnement (`"PVE_TOKEN_SECRET"`),
/// gabarit (`"<token>"`).
fn is_reference_value(assignment: &str) -> bool {
    let Some(start) = assignment.find(['"', '\'']) else {
        return false;
    };
    let value = assignment[start + 1..assignment.len() - 1].trim();
    value.starts_with('$')
        || value.starts_with('<')
        || (value.starts_with('%') && value.ends_with('%'))
        || (value.len() >= 3
            && value.starts_with(|c: char| c.is_ascii_uppercase())
            && value
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
}

impl Scanner for SecretsScanner {
    fn name(&self) -> &str {
        "secrets"
    }
    fn category(&self) -> Category {
        Category::Secrets
    }
    fn scan(&self, target: &Path) -> Vec<Finding> {
        let rules = secret_rules();
        let files = walk::walk_files(target);
        let mut findings = Vec::new();

        for file_path in &files {
            let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if SKIP_FILES.contains(&file_name) {
                continue;
            }

            if file_path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| SKIP_EXTENSIONS.contains(&ext))
            {
                continue;
            }

            let relative = file_path
                .strip_prefix(target)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            if is_test_or_fixture(&relative) {
                continue;
            }

            let content = match fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for (line_num, line) in content.lines().enumerate() {
                if line.len() > 2000 {
                    continue;
                }
                if is_allowlisted(line) {
                    continue;
                }

                for rule in &rules {
                    if let Some(m) = rule.regex.find(line) {
                        if rule.id == "password-assignment" && is_reference_value(m.as_str()) {
                            continue;
                        }
                        findings.push(Finding {
                            severity: rule.severity,
                            category: Category::Secrets,
                            scanner: "secrets".into(),
                            title: format!("{} ({})", rule.description, rule.id),
                            file: Some(relative.clone()),
                            line: Some((line_num + 1) as u32),
                            detail: None,
                        });
                        break;
                    }
                }
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_to_a_secret_are_not_the_secret() {
        assert!(is_reference_value(r#"PASSWORD="$(openssl rand -hex 32)""#));
        assert!(is_reference_value(r#"DB_PASSWORD="$DB_PASSWORD""#));
        assert!(is_reference_value("$secret: '%app.secret%'"));
        assert!(is_reference_value(r#"EnvToken = "CF_API_TOKEN""#));
        assert!(!is_reference_value(r#"password: "Xk2!pq9Lm""#));
    }
}
