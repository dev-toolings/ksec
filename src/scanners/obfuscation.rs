use crate::scanner::{Category, Finding, Scanner, Severity};
use crate::walk;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub struct ObfuscationScanner;

/// Les campagnes 2025-2026 (GlassWorm, Shai-Hulud, obfuscator.io sur npm,
/// chargeurs PyPI en une ligne) ne cachent plus leur charge dans un fichier de
/// config : elle est dans `dist/index.js` d'une dépendance, dans l'extension
/// d'un éditeur ou dans un `.pth`. On regarde donc tout le code, dépendances
/// comprises.
const CODE_EXTENSIONS: &[&str] = &["js", "cjs", "mjs", "jsx", "ts", "tsx", "py", "pth"];

/// `bun_environment.js` pèse ~10 Mo ; au-delà de 32 Mo ce n'est plus du code
/// qu'on lit ligne à ligne mais un artefact.
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;

/// En dessous, une suite de caractères invisibles s'explique (drapeau emoji à
/// tags, sélecteur de variation après un emoji). Au-dessus, c'est un octet de
/// charge par caractère : la technique GlassWorm.
const INVISIBLE_RUN_THRESHOLD: usize = 16;

/// Le nommage `_0x1a2b` d'obfuscator.io : un bundle minifié classique n'en
/// produit pas, un fichier obfusqué en aligne des centaines.
const OBFUSCATOR_ID_THRESHOLD: usize = 30;

const CONFIG_PATTERNS: &[&str] = &[
    "*.config.js",
    "*.config.mjs",
    "*.config.cjs",
    "*.config.ts",
    ".eslintrc.js",
    ".prettierrc.js",
    "rollup.config.*",
    "vite.config.*",
    "webpack.config.*",
    "next.config.*",
    "nuxt.config.*",
    "tailwind.config.*",
    "postcss.config.*",
    "jest.config.*",
];

static EXEC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:eval|exec|execScript|Function|runInThisContext|runInNewContext|createScript)\s*\(",
    )
    .unwrap()
});

static DECODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b(?:atob|b64decode|b85decode|a85decode|b32decode|decompress|marshal\.loads|fromhex|unhexlify|codePointAt)\s*\(|\bcodecs\.decode\s*\(|Buffer\.from\s*\([^)]{0,400}['"](?:base64|hex)['"]|\[::-1\]"#,
    )
    .unwrap()
});

static OBFUSCATOR_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b_0x[0-9a-f]{4,6}\b").unwrap());

/// Rotation du tableau de chaînes d'obfuscator.io :
/// `_0x1f2e['push'](_0x1f2e['shift']())` dans une boucle `while(!![])`.
static STRING_ARRAY_ROTATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\[['"]push['"]\]\(\s*_0x\w+\[['"]shift['"]\]\(\)\s*\)|while\s*\(\s*!!\[\]\s*\)"#)
        .unwrap()
});

/// Le stager qui se tait en CI puis se détache de `npm install` (Microsoft,
/// mai 2026) : seul, ce motif est banal (update-notifier fait pareil), il ne
/// sert qu'à aggraver un fichier déjà obfusqué.
static CI_EVASION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"process\.env\.CI\b|env\[['"]CI['"]\]|GITHUB_ACTIONS|\bis-ci\b"#).unwrap()
});
static DETACHED_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.unref\(\)|detached\s*:\s*(?:true|!0)").unwrap());

static PTH_EXEC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:b64decode|base64|marshal|zlib|fromhex|codecs|subprocess|urlopen|urllib|socket|requests)\b",
    )
    .unwrap()
});

static GLOBAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"global\[|_\$_[0-9a-f]"#).unwrap());
static HEX_HEAVY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){20,}").unwrap());

fn is_config_file(filename: &str) -> bool {
    CONFIG_PATTERNS.iter().any(|pat| {
        let pat_clean = pat.replace("*", "");
        if pat.starts_with('*') && pat.ends_with('*') {
            filename.contains(pat_clean.trim_matches('.'))
        } else if pat.starts_with('*') {
            filename.ends_with(&pat_clean)
        } else if pat.ends_with('*') {
            filename.starts_with(&pat_clean)
        } else {
            filename == pat_clean || filename == *pat
        }
    })
}

/// Caractères qui ne s'affichent pas et qu'un décodeur relit octet par octet.
///
/// Les sélecteurs de variation et les tags sont la technique GlassWorm : une
/// rafale n'a aucune raison d'exister dans du code. La zone à usage privé et
/// les espaces de largeur nulle, eux, peuplent des tables légitimes (pages de
/// code de SheetJS, polices d'icônes) : ils ne comptent qu'à côté d'un
/// décodeur et d'un eval.
#[derive(Clone, Copy, PartialEq)]
enum Invisible {
    Selector,
    Private,
}

fn invisible_kind(c: char) -> Option<Invisible> {
    match c as u32 {
        0xFE00..=0xFE0F | 0xE0100..=0xE01EF | 0xE0000..=0xE007F => Some(Invisible::Selector),
        0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x200B..=0x200D | 0x2060..=0x2064 => {
            Some(Invisible::Private)
        }
        _ => None,
    }
}

fn line_len_at(content: &str, i: usize) -> usize {
    let start = content[..i].rfind('\n').map_or(0, |p| p + 1);
    let end = content[i..].find('\n').map_or(content.len(), |p| i + p);
    end - start
}

/// Contrôles bidirectionnels (Trojan Source, CVE-2021-42574) : le code relu à
/// l'écran n'est pas celui que le compilateur exécute.
fn is_bidi_control(c: char) -> bool {
    matches!(c as u32, 0x202A..=0x202E | 0x2066..=0x2069)
}

/// Appels d'exécution dynamique, sans les méthodes homonymes : `re.exec(`
/// (RegExp) et `cursor.execute` sont partout dans un bundle minifié.
fn exec_calls(text: &str) -> impl Iterator<Item = regex::Match<'_>> {
    EXEC_RE.find_iter(text).filter(move |m| {
        let vm = text[m.start()..].starts_with("run") || text[m.start()..].starts_with("create");
        vm || m.start() == 0 || text.as_bytes()[m.start() - 1] != b'.'
    })
}

fn line_of(content: &str, byte_offset: usize) -> u32 {
    (content[..byte_offset]
        .bytes()
        .filter(|b| *b == b'\n')
        .count()
        + 1) as u32
}

/// Longue ligne quasi exclusivement base64. Les `data:` URI (polices, wasm,
/// images) et les source maps sont des blobs légitimes : on les écarte.
fn encoded_blob_line(content: &str) -> Option<usize> {
    let mut offset = 0;
    for line in content.split_inclusive('\n') {
        let len = line.len();
        // `AGFzbQ` = base64 de `\0asm` : un module WebAssembly embarqué
        // (undici, vite, lexers), pas du code qu'on exécute via eval.
        if len > 2000
            && !line.contains("data:")
            && !line.contains("sourceMappingURL")
            && !line.contains("AGFzbQ")
        {
            let b64 = line
                .bytes()
                .filter(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
                .count();
            // Une police ou une table passée à `toByteArray` n'est pas une
            // charge : on ne retient que le blob donné à eval/exec sur sa ligne.
            if b64 * 100 >= len * 95 && exec_calls(line).next().is_some() {
                return Some(offset);
            }
        }
        offset += len;
    }
    None
}

fn finding(
    severity: Severity,
    rule: &str,
    title: String,
    file: &str,
    line: Option<u32>,
    detail: Option<String>,
) -> Finding {
    Finding {
        severity,
        category: Category::Obfuscation,
        scanner: "obfuscation".into(),
        title: format!("{title} ({rule})"),
        file: Some(file.to_string()),
        line,
        detail,
    }
}

/// Analyse d'un fichier de code. Séparée du parcours pour être testable.
pub fn scan_content(relative: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let is_pth = relative.ends_with(".pth");
    let has_exec = exec_calls(content).next().is_some();

    // Caractères invisibles en rafale.
    let mut run = 0usize;
    let mut run_start = 0usize;
    let mut run_kind = Invisible::Private;
    let mut best: [Option<(usize, usize)>; 2] = [None, None];
    let mut bidi_at: Option<usize> = None;
    for (i, c) in content.char_indices() {
        match invisible_kind(c) {
            Some(kind) => {
                if run == 0 || kind != run_kind {
                    run = 0;
                    run_start = i;
                    run_kind = kind;
                }
                run += 1;
                let slot = &mut best[kind as usize];
                if run >= INVISIBLE_RUN_THRESHOLD && slot.is_none_or(|(_, n)| run > n) {
                    *slot = Some((run_start, run));
                }
            }
            None => run = 0,
        }
        // Une table de décodage HTML ou Unicode tient sur une ligne de
        // plusieurs milliers de caractères ; Trojan Source vise du code lisible.
        if bidi_at.is_none() && is_bidi_control(c) && line_len_at(content, i) < 1000 {
            bidi_at = Some(i);
        }
    }
    let decoder = content.contains("codePointAt");
    let hidden = match best {
        [Some((at, n)), _] => Some((at, n, has_exec || decoder)),
        [None, Some((at, n))] if has_exec && decoder => Some((at, n, true)),
        _ => None,
    };
    if let Some((at, n, armed)) = hidden {
        let (severity, detail) = if armed {
            (
                Severity::Critical,
                "invisible characters next to a decoder/eval: GlassWorm-style hidden payload",
            )
        } else {
            (
                Severity::High,
                "invisible characters carry bytes that code review does not show",
            )
        };
        out.push(finding(
            severity,
            "invisible-unicode-payload",
            format!("{n} consecutive invisible Unicode characters"),
            relative,
            Some(line_of(content, at)),
            Some(detail.into()),
        ));
    }
    // Trojan Source vise le code qu'un humain relit en revue : celui du projet.
    // Dans une dépendance, ces caractères peuplent des regex Unicode et des
    // chaînes i18n (react-aria, katex, spacy).
    if let Some(at) = bidi_at.filter(|_| !walk::is_dependency_path(relative)) {
        out.push(finding(
            Severity::High,
            "bidi-control",
            "bidirectional control character in source (Trojan Source)".into(),
            relative,
            Some(line_of(content, at)),
            None,
        ));
    }

    // Décodage puis exécution sur la même ligne : le chargeur une ligne de
    // PyPI (inverse + base64 + zlib/marshal + exec) et `eval(atob(...))`.
    let mut offset = 0;
    let mut chain_found = false;
    for line in content.split_inclusive('\n') {
        if !chain_found {
            let near = exec_calls(line).any(|e| {
                DECODE_RE
                    .find_iter(line)
                    .any(|d| d.start().abs_diff(e.start()) <= 400)
            });
            if near {
                out.push(finding(
                    Severity::Critical,
                    "decode-exec-chain",
                    "decoded payload passed straight to eval/exec".into(),
                    relative,
                    Some(line_of(content, offset)),
                    None,
                ));
                chain_found = true;
            }
        }
        offset += line.len();
    }

    // obfuscator.io.
    let ids = OBFUSCATOR_ID_RE
        .find_iter(content)
        .take(OBFUSCATOR_ID_THRESHOLD)
        .count();
    let obfuscator = ids >= OBFUSCATOR_ID_THRESHOLD;
    if obfuscator {
        let rotation = STRING_ARRAY_ROTATION_RE.find(content);
        let first = OBFUSCATOR_ID_RE
            .find(content)
            .map(|m| m.start())
            .unwrap_or(0);
        let (severity, title) = match rotation {
            Some(_) => (
                Severity::Critical,
                "obfuscator.io string array with rotation",
            ),
            None => (Severity::High, "obfuscator.io-style _0x identifiers"),
        };
        out.push(finding(
            severity,
            "obfuscator-io",
            title.into(),
            relative,
            Some(line_of(
                content,
                rotation.map(|m| m.start()).unwrap_or(first),
            )),
            None,
        ));
    }

    // Blob encodé passé à eval/exec sur la même ligne.
    if let Some(at) = encoded_blob_line(content) {
        out.push(finding(
            Severity::High,
            "encoded-blob-exec",
            "large base64 blob fed to eval/exec/Function".into(),
            relative,
            Some(line_of(content, at)),
            None,
        ));
    }

    // `.pth` : exécuté à chaque démarrage de Python, sans import.
    if is_pth {
        let mut offset = 0;
        for line in content.split_inclusive('\n') {
            let t = line.trim_start();
            if t.starts_with("import") && PTH_EXEC_RE.is_match(t) {
                out.push(finding(
                    Severity::Critical,
                    "pth-startup-exec",
                    ".pth file runs code at every Python start".into(),
                    relative,
                    Some(line_of(content, offset)),
                    None,
                ));
                break;
            }
            offset += line.len();
        }
    }

    // Un fichier déjà suspect qui se tait en CI et se détache du processus
    // parent : c'est le stager, pas un outil.
    if !out.is_empty() && CI_EVASION_RE.is_match(content) && DETACHED_RE.is_match(content) {
        for f in &mut out {
            f.severity = Severity::Critical;
            f.detail = Some(match f.detail.take() {
                Some(d) => format!("{d}; exits under CI and runs detached"),
                None => "exits under CI and runs detached".into(),
            });
        }
    }

    out
}

/// Heuristiques historiques, réservées aux fichiers de config où une ligne de
/// 500 caractères n'a rien à faire.
fn scan_config(relative: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (line_num, line) in content.lines().enumerate() {
        let line_no = Some((line_num + 1) as u32);
        if line.len() > 500 {
            let trimmed = line.trim();
            let looks_like_data = trimmed.starts_with('{')
                || trimmed.starts_with('[')
                || trimmed.starts_with("//")
                || trimmed.contains("sourceMap")
                || trimmed.contains("webpack");
            let severity = if looks_like_data || line.len() < 1000 {
                Severity::Medium
            } else {
                Severity::High
            };
            out.push(finding(
                severity,
                "config-long-line",
                format!("line >500 chars ({} chars) in config file", line.len()),
                relative,
                line_no,
                None,
            ));
        }
        if GLOBAL_RE.is_match(line) {
            out.push(finding(
                Severity::High,
                "config-global-accessor",
                "suspicious global[] or _$_ pattern".into(),
                relative,
                line_no,
                None,
            ));
        }
        if HEX_HEAVY_RE.is_match(line) {
            out.push(finding(
                Severity::High,
                "config-hex-payload",
                "heavy hex-encoded content in config".into(),
                relative,
                line_no,
                None,
            ));
        }
    }
    out
}

fn scan_file(target: &Path, file_path: &Path) -> Vec<Finding> {
    let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    let config = is_config_file(filename);
    let code = CODE_EXTENSIONS.contains(&ext.as_str()) && !filename.ends_with(".d.ts");
    if !config && !code {
        return Vec::new();
    }
    if fs::metadata(file_path).is_ok_and(|m| m.len() > MAX_FILE_BYTES) {
        return Vec::new();
    }
    let Ok(bytes) = fs::read(file_path) else {
        return Vec::new();
    };
    let content = String::from_utf8_lossy(&bytes);
    let relative = file_path
        .strip_prefix(target)
        .unwrap_or(file_path)
        .to_string_lossy()
        .to_string();

    let mut out = if code {
        scan_content(&relative, &content)
    } else {
        Vec::new()
    };
    if config {
        out.extend(scan_config(&relative, &content));
    }
    out
}

impl Scanner for ObfuscationScanner {
    fn name(&self) -> &str {
        "obfuscation"
    }
    fn category(&self) -> Category {
        Category::Obfuscation
    }
    fn scan(&self, target: &Path) -> Vec<Finding> {
        let files: Vec<PathBuf> = walk::walk_files_including_deps(target);
        let workers = std::thread::available_parallelism().map_or(4, |n| n.get());
        let chunk = files.len().div_ceil(workers).max(1);

        let mut findings: Vec<Finding> = std::thread::scope(|s| {
            let handles: Vec<_> = files
                .chunks(chunk)
                .map(|part| {
                    s.spawn(move || {
                        part.iter()
                            .flat_map(|f| scan_file(target, f))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap_or_default())
                .collect()
        });
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.file.cmp(&b.file))
        });
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(found: &[Finding]) -> Vec<String> {
        found.iter().map(|f| f.title.clone()).collect()
    }

    #[test]
    fn glassworm_invisible_payload_with_decoder_is_critical() {
        let hidden: String = (0..40)
            .map(|i| char::from_u32(0xFE00 + (i % 16)).unwrap())
            .collect();
        let src = format!(
            "const s = `{hidden}`;\nconst b = [...s].map(c => c.codePointAt(0) - 0xFE00);\neval(Buffer.from(b).toString());\n"
        );
        let found = scan_content("dist/extension.js", &src);
        let f = found
            .iter()
            .find(|f| f.title.contains("invisible-unicode-payload"))
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.line, Some(1));
    }

    #[test]
    fn emoji_variation_selectors_and_flag_tags_are_not_flagged() {
        let src = "const ok = '❤️ ✔️ 🏴\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}';\n";
        assert!(scan_content("src/emoji.ts", src).is_empty());
    }

    #[test]
    fn codepage_tables_in_private_use_area_are_not_flagged() {
        let table: String = (0..64)
            .map(|i| char::from_u32(0xE000 + i).unwrap())
            .collect();
        let src = format!(
            "var d = \"{table}\"; for (i = 0; i < d.length; ++i) e[d.charCodeAt(i)] = i;\n"
        );
        assert!(scan_content("node_modules/codepage/bits/10001.js", &src).is_empty());
    }

    #[test]
    fn pypi_one_line_loader_is_flagged() {
        let src = "import base64,zlib;exec(zlib.decompress(base64.b64decode(b'eJzLSM3JyQcABiwCFQ=='[::-1])))\n";
        let found = scan_content("pymem/__init__.py", src);
        assert!(
            rules(&found)
                .iter()
                .any(|t| t.contains("decode-exec-chain")),
            "{found:?}"
        );
    }

    #[test]
    fn obfuscator_io_rotation_is_critical() {
        let ids: String = (0..40)
            .map(|i| format!("var _0x{:04x}=1;", 0x1a00 + i))
            .collect();
        let src = format!(
            "{ids}\n(function(_0x1a00){{while(!![]){{_0x1a00['push'](_0x1a00['shift']());}}}})();\n"
        );
        let found = scan_content("node_modules/evil/index.js", &src);
        let f = found
            .iter()
            .find(|f| f.title.contains("obfuscator-io"))
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn wasm_data_uri_and_plain_minified_code_are_not_flagged() {
        let blob = "A".repeat(5000);
        let src = format!(
            "var w='data:application/wasm;base64,{blob}';var f=new Function('return this')();\nfunction a(b){{return b+1}}\n"
        );
        assert!(scan_content("node_modules/sql.js/dist/sql-wasm.js", &src).is_empty());
    }

    #[test]
    fn base64_blob_is_flagged_only_when_fed_to_eval() {
        let blob = "QUJD".repeat(1000);
        let font =
            format!("var data = base64.toByteArray(\"{blob}\");\nnew Function('x', 'return x');\n");
        assert!(scan_content("node_modules/@vercel/og/index.js", &font).is_empty());
        let evil = format!("eval(require('zlib').inflateSync(\"{blob}\"));\n");
        let found = scan_content("node_modules/x/index.js", &evil);
        assert!(
            rules(&found)
                .iter()
                .any(|t| t.contains("encoded-blob-exec")),
            "{found:?}"
        );
    }

    #[test]
    fn malicious_pth_is_critical_and_editable_install_is_not() {
        let evil = "import os,base64;exec(base64.b64decode('cHJpbnQoMSk='))\n";
        assert!(
            rules(&scan_content("site-packages/x.pth", evil))
                .iter()
                .any(|t| t.contains("pth-startup-exec"))
        );
        let ok = "import __editable___foo_finder; __editable___foo_finder.install()\n";
        assert!(scan_content("site-packages/__editable__.foo.pth", ok).is_empty());
        let coverage = r#"import sys; exec('import os\nif os.getenv("COVERAGE_PROCESS_START"):\n import coverage')"#;
        assert!(scan_content("site-packages/a1_coverage.pth", coverage).is_empty());
    }

    #[test]
    fn ci_aware_detached_stager_is_escalated() {
        let ids: String = (0..40)
            .map(|i| format!("var _0x{:04x}=1;", 0x2b00 + i))
            .collect();
        let src = format!(
            "{ids}\nif(!process.env.CI){{require('child_process').spawn(n,[f],{{detached:true}}).unref();}}\n"
        );
        let found = scan_content("node_modules/x/setup.js", &src);
        assert!(
            found.iter().all(|f| f.severity == Severity::Critical),
            "{found:?}"
        );
    }
}
