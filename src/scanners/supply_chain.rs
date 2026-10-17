use crate::rules::supply_chain::supply_chain_patterns;
use crate::scanner::{Category, Finding, Scanner, Severity};
use crate::walk;
use std::fs;
use std::path::Path;

pub struct SupplyChainScanner;

const JS_EXTENSIONS: &[&str] = &["js", "cjs", "mjs", "ts", "tsx", "jsx"];

/// Un fichier ne devient une alerte que si son contenu le trahit.
///
/// Le nom seul ne prouve rien : `Math_Symbol.js` est aussi une table Unicode
/// parfaitement légitime de `regenerate-unicode-properties`, et `setup.mjs` est
/// un module de `motion-dom`. Les deux sont présents dans n'importe quel projet
/// front un peu fourni, donc alerter sur le nom produit un CRITICAL faux à
/// chaque scan.
fn looks_malicious(content: &str) -> bool {
    content.contains("execFileSync")
        || content.contains("child_process")
        || content.contains("oven-sh/bun")
        || content.contains("releases/download")
        || content.contains("webhook.site")
        || has_encoded_blob(content)
}

/// Une longue ligne quasi exclusivement alphanumérique : charge encodée en
/// base64. Du JS minifié atteint la même longueur mais reste truffé de
/// ponctuation, ce qui le fait passer sous le seuil.
fn has_encoded_blob(content: &str) -> bool {
    content.lines().any(|line| {
        line.len() > 1000
            && line
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
                .count()
                * 10
                >= line.len() * 9
    })
}

fn scan_known_malware_files(target: &Path, findings: &mut Vec<Finding>) {
    // `setup_bun.js` / `bun_environment.js` : Shai-Hulud 2.0, le preinstall
    // installe Bun pour lancer la charge hors des garde-fous de Node.
    const IOC_FILES: &[&str] = &[
        "Math_Symbol.js",
        "math_init.js",
        "setup.mjs",
        "setup_bun.js",
        "bun_environment.js",
    ];
    // Ce scan est le seul à descendre dans les dépendances installées : c'est
    // là, et nulle part ailleurs, que la charge est déposée.
    let files = walk::walk_files_including_deps(target);

    for file_path in &files {
        let name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if IOC_FILES.contains(&name) {
            let relative = file_path
                .strip_prefix(target)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            // La charge de Shai-Hulud 2.0 pèse ~10 Mo d'obfuscator.io : sa
            // taille la trahit autant que son contenu.
            let flagged = (name == "bun_environment.js"
                && fs::metadata(file_path).is_ok_and(|m| m.len() > 1024 * 1024))
                || fs::read_to_string(file_path).is_ok_and(|c| looks_malicious(&c));

            if flagged {
                findings.push(Finding {
                    severity: Severity::Critical,
                    category: Category::SupplyChain,
                    scanner: "supply-chain".into(),
                    title: format!("known Shai-Hulud dropper/payload file: {name}"),
                    file: Some(relative),
                    line: None,
                    detail: Some(
                        "Indicator matches the Shai-Hulud worm family (2.0 Bun loader, keyv Aug 2026)"
                            .into(),
                    ),
                });
            }
        }
    }
}

fn scan_package_jsons(target: &Path, findings: &mut Vec<Finding>) {
    let patterns = supply_chain_patterns();
    let install_patterns: Vec<_> = patterns
        .iter()
        .filter(|p| p.id.contains("install") || p.id.contains("postinstall"))
        .collect();

    let files = walk::walk_files(target);
    for file_path in &files {
        if file_path.file_name().and_then(|n| n.to_str()) != Some("package.json") {
            continue;
        }

        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let relative = file_path
            .strip_prefix(target)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        let parsed: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(scripts) = parsed.get("scripts").and_then(|s| s.as_object()) {
            for (key, val) in scripts {
                let script_val = val.as_str().unwrap_or("");
                let is_lifecycle = matches!(
                    key.as_str(),
                    "preinstall" | "install" | "postinstall" | "preuninstall" | "postuninstall"
                );

                if is_lifecycle && !script_val.is_empty() {
                    for pat in &install_patterns {
                        if pat.regex.is_match(script_val) || pat.regex.is_match(&content) {
                            findings.push(Finding {
                                severity: Severity::High,
                                category: Category::SupplyChain,
                                scanner: "supply-chain".into(),
                                title: format!(
                                    "{} in {} script ({})",
                                    pat.description, key, pat.id
                                ),
                                file: Some(relative.clone()),
                                line: None,
                                detail: Some(format!("{key}: {script_val}")),
                            });
                        }
                    }

                    if script_val.contains("curl ")
                        || script_val.contains("wget ")
                        || script_val.contains("http://")
                        || script_val.contains("https://")
                    {
                        findings.push(Finding {
                            severity: Severity::High,
                            category: Category::SupplyChain,
                            scanner: "supply-chain".into(),
                            title: format!("network access in {key} script"),
                            file: Some(relative.clone()),
                            line: None,
                            detail: Some(format!("{key}: {script_val}")),
                        });
                    }
                }
            }
        }
    }
}

impl Scanner for SupplyChainScanner {
    fn name(&self) -> &str {
        "supply-chain"
    }
    fn category(&self) -> Category {
        Category::SupplyChain
    }
    fn scan(&self, target: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = supply_chain_patterns();

        scan_package_jsons(target, &mut findings);
        scan_known_malware_files(target, &mut findings);

        let files = walk::walk_files_with_extensions(target, JS_EXTENSIONS);

        for file_path in &files {
            let content = match fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let relative = file_path
                .strip_prefix(target)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            if relative.starts_with("node_modules/")
                || relative.contains("/test/")
                || relative.contains("/tests/")
                || relative.contains("/__tests__/")
                || relative.contains("/fixtures/")
                || relative.contains("/examples/")
                || relative.ends_with(".test.js")
                || relative.ends_with(".test.ts")
                || relative.ends_with(".spec.js")
                || relative.ends_with(".spec.ts")
                || relative.ends_with(".min.js")
                || relative.ends_with(".d.ts")
            {
                continue;
            }

            for (line_num, line) in content.lines().enumerate() {
                if line.len() > 5000 {
                    continue;
                }
                let trimmed = line.trim();
                if trimmed.starts_with("//")
                    || trimmed.starts_with("/*")
                    || trimmed.starts_with('*')
                    || trimmed.contains("assert")
                    || trimmed.contains("expect(")
                    || trimmed.contains("describe(")
                {
                    continue;
                }
                for pat in &patterns {
                    if pat.regex.is_match(line) {
                        findings.push(Finding {
                            severity: Severity::Medium,
                            category: Category::SupplyChain,
                            scanner: "supply-chain".into(),
                            title: format!("{} ({})", pat.description, pat.id),
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
    use super::{has_encoded_blob, looks_malicious};

    #[test]
    fn legit_unicode_table_is_not_flagged() {
        // regenerate-unicode-properties/General_Category/Math_Symbol.js : porte
        // un nom d'indicateur connu, mais n'est qu'une table de points de code.
        let content = "const set = require('regenerate')(0x2B, 0x7C, 0x7E, 0xAC, 0xB1, 0xD7);\n\
                       module.exports = set;\n";
        assert!(!looks_malicious(content));
    }

    #[test]
    fn legit_motion_dom_setup_is_not_flagged() {
        let content = "import { resolveElements } from '../../utils/resolve-elements.mjs';\n\
                       function setupGesture(elementOrSelector, options) {\n\
                       const gestureAbortController = new AbortController();\n\
                       }\n\
                       export { setupGesture };\n";
        assert!(!looks_malicious(content));
    }

    #[test]
    fn dropper_spawning_a_process_is_flagged() {
        let content = "import { execFileSync } from 'child_process';\n\
                       execFileSync('curl', ['-sL', 'https://github.com/oven-sh/bun/releases/download/x/bun']);\n";
        assert!(looks_malicious(content));
    }

    #[test]
    fn long_base64_payload_is_flagged() {
        let content = format!("const d=\"{}\";", "QUJDRGVmZ2hpams".repeat(100));
        assert!(has_encoded_blob(&content));
    }

    #[test]
    fn minified_javascript_is_not_mistaken_for_a_payload() {
        // Du JS minifié dépasse aussi les 1000 caractères sur une ligne : c'est
        // sa ponctuation qui doit le faire passer sous le seuil, pas sa taille.
        let content = "!function(e,t){for(var n=0;n<e.length;n++){t[n]=e[n].call(null,n),\
                       e[n]=null}}(a,b),c.d={e:1,f:2},"
            .repeat(30);
        assert!(content.len() > 1000);
        assert!(!has_encoded_blob(&content));
    }
}
