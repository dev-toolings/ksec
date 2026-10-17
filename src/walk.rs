use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use std::fs;
use std::path::{Path, PathBuf};

const SKIP_DIRS: &[&str] = &[
    // package managers
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    ".tox",
    // build outputs
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".output",
    "target",
    "__pycache__",
    "coverage",
    ".nyc_output",
    // VCS
    ".git",
    // IDE / editor runtimes
    ".cursor-server",
    ".vscode-server",
    ".vscode",
    ".cursor",
    ".idea",
    // tool caches (pure noise, no user code)
    ".cache",
    ".local",
    ".npm",
    ".bun",
    ".cargo",
    ".rustup",
    "snap",
    ".oh-my-zsh",
    ".codex",
    ".nvm",
    ".pyenv",
    ".gradle",
    ".m2",
    ".docker",
    // Go module cache (library code, not user code)
    "pkg",
    // browser internals
    "google-chrome",
    "chromium",
    "firefox",
    "BraveSoftware",
    // Claude Code internals (history, plugins, sessions)
    "file-history",
    "plugins",
    "worktrees",
    // auto-generated docs
    ".next-docs",
];

const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "svg", "bmp", "tiff", "mp3", "mp4", "avi", "mov",
    "mkv", "flac", "wav", "ogg", "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "woff", "woff2",
    "ttf", "eot", "otf", "pdf", "doc", "docx", "xls", "xlsx", "exe", "dll", "so", "dylib", "o",
    "a", "wasm", "pyc", "pyo", "class", "sqlite", "db",
];

/// Répertoires où atterrit du code tiers installé : un dropper ne se pose
/// jamais dans le code du projet, il se pose là. `extensions` couvre les
/// extensions VS Code / Cursor (GlassWorm), `site-packages` les paquets Python
/// (fichiers `.pth` exécutés au démarrage de l'interpréteur).
const DEP_ROOTS: &[&str] = &[
    "node_modules",
    "site-packages",
    "dist-packages",
    "extensions",
];

/// Dossiers de SKIP_DIRS qu'il faut traverser pour atteindre un DEP_ROOTS :
/// `.venv/lib/python3.x/site-packages`, `.vscode/extensions`.
const DEP_CONTAINERS: &[&str] = &[".venv", "venv"];
const EDITOR_DIRS: &[&str] = &[".vscode", ".vscode-server", ".cursor", ".cursor-server"];

/// Chemin relatif qui tombe dans du code tiers installé.
pub fn is_dependency_path(relative: &str) -> bool {
    inside_dep_root(Path::new(relative))
}

fn inside_dep_root(path: &Path) -> bool {
    let parts: Vec<_> = path.components().map(|c| c.as_os_str()).collect();
    parts.iter().enumerate().any(|(i, c)| {
        if *c == "extensions" {
            // `extensions` n'est un magasin de code tiers que sous un éditeur.
            i > 0
                && parts[i - 1]
                    .to_str()
                    .is_some_and(|p| EDITOR_DIRS.contains(&p))
        } else {
            DEP_ROOTS.iter().any(|r| *c == *r)
        }
    })
}

fn load_ksecignore(target: &Path) -> Option<ignore::overrides::Override> {
    let ignore_path = target.join(".ksecignore");
    let content = fs::read_to_string(&ignore_path).ok()?;
    let mut builder = OverrideBuilder::new(target);
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // .ksecignore uses gitignore syntax but means "exclude"
        // override builder uses "!" to negate (include), so we invert:
        // a pattern "foo" in .ksecignore means exclude foo → override "!foo"
        let pattern = if trimmed.starts_with('!') {
            // negation in .ksecignore = re-include → no prefix in override
            trimmed.strip_prefix('!').unwrap_or(trimmed).to_string()
        } else {
            format!("!{trimmed}")
        };
        builder.add(&pattern).ok();
    }
    builder.build().ok()
}

pub fn walk_files(target: &Path) -> Vec<PathBuf> {
    collect(target, false)
}

/// Même parcours que `walk_files`, mais qui entre dans les `node_modules`.
///
/// Réservé à la recherche d'indicateurs de compromission : un dropper de la
/// chaîne d'approvisionnement n'atterrit jamais dans le code du projet, il
/// atterrit dans une dépendance installée. Les autres scanners doivent garder
/// `walk_files`, sinon `secrets` et `sast` remontent le bruit de dizaines de
/// milliers de paquets.
pub fn walk_files_including_deps(target: &Path) -> Vec<PathBuf> {
    collect(target, true)
}

fn collect(target: &Path, include_deps: bool) -> Vec<PathBuf> {
    let overrides = load_ksecignore(target);

    let mut files = Vec::new();
    let mut builder = WalkBuilder::new(target);
    builder
        .hidden(false)
        // `node_modules` est presque toujours dans le .gitignore. Pour aller y
        // chercher un dropper il ne suffit donc pas de le retirer de SKIP_DIRS,
        // il faut aussi désarmer le filtre git.
        .git_ignore(!include_deps)
        .git_global(false)
        .git_exclude(!include_deps)
        .filter_entry(move |entry| {
            let Some(name) = entry.file_name().to_str() else {
                return true;
            };
            if !entry.file_type().is_some_and(|ft| ft.is_dir()) {
                return true;
            }
            if include_deps {
                if DEP_ROOTS.contains(&name)
                    || DEP_CONTAINERS.contains(&name)
                    || EDITOR_DIRS.contains(&name)
                {
                    return true;
                }
                // Une fois à l'intérieur d'un node_modules, plus aucun filtre de
                // bruit : la charge se cache justement dans `dist/` et le magasin
                // de bun est un `.bun/`, deux noms présents dans SKIP_DIRS.
                if inside_dep_root(entry.path()) {
                    return name != ".git";
                }
            }
            !SKIP_DIRS.contains(&name)
        });

    if let Some(ref ov) = overrides {
        builder.overrides(ov.clone());
    }

    let walker = builder.build();

    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        let path = entry.path();
        if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|ext| BINARY_EXTENSIONS.contains(&ext.to_lowercase().as_str()))
        {
            continue;
        }
        files.push(path.to_path_buf());
    }
    files
}

pub fn walk_files_with_extensions(target: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    walk_files(target)
        .into_iter()
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| extensions.contains(&ext.to_lowercase().as_str()))
        })
        .collect()
}
