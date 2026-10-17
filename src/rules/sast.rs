use crate::scanner::Severity;
use regex::Regex;

pub struct SastRule {
    pub id: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub regex: Regex,
    pub extensions: &'static [&'static str],
}

const JS_TS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs"];
const PY: &[&str] = &["py"];
const PHP: &[&str] = &["php"];
const ALL_WEB: &[&str] = &[
    "js", "jsx", "ts", "tsx", "mjs", "cjs", "py", "php", "rb", "go", "rs",
];

pub fn sast_rules() -> Vec<SastRule> {
    use Severity::*;

    let defs: Vec<(&str, &str, Severity, &str, &[&str])> = vec![
        // SQL Injection — only flag when user input markers are present
        (
            "sql-injection-concat",
            "SQL injection - user input in query",
            High,
            r#"(?i)(?:execute|query|raw)\s*\(\s*[`'"]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^`'"]*\$\{(?:req\b|params\b|query\b|body\b|input\b|args\b|user)"#,
            JS_TS,
        ),
        (
            "sql-injection-fstring",
            "SQL injection - f-string with user input",
            High,
            r#"(?i)(?:execute|cursor\.execute)\s*\(\s*f['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^'"]*\{(?:request\b|params\b|args\b|kwargs\b|user_|input)"#,
            PY,
        ),
        (
            "sql-injection-format",
            "SQL injection - .format() in query",
            High,
            r#"(?i)(?:execute|cursor\.execute)\s*\(\s*['"].*(?:SELECT|INSERT|UPDATE|DELETE)\b.*['"]\.format\s*\("#,
            PY,
        ),
        (
            "sql-injection-concat-php",
            "SQL injection - concatenation in PHP query",
            High,
            r#"(?i)\$(?:pdo|conn|db|mysqli)->(?:query|prepare|exec)\s*\(\s*['"].*\.\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)"#,
            PHP,
        ),
        // XSS
        (
            "xss-innerhtml",
            "XSS - innerHTML assignment",
            High,
            r#"\.innerHTML\s*="#,
            JS_TS,
        ),
        (
            "xss-dangerously-set",
            "XSS - dangerouslySetInnerHTML",
            Medium,
            r#"dangerouslySetInnerHTML"#,
            JS_TS,
        ),
        (
            "xss-document-write",
            "XSS - document.write()",
            Medium,
            r#"document\.write\s*\("#,
            JS_TS,
        ),
        (
            "xss-outerhtml",
            "XSS - outerHTML assignment",
            High,
            r#"\.outerHTML\s*="#,
            JS_TS,
        ),
        // Command Injection
        (
            "cmd-injection-exec",
            "Command injection - exec/execSync with user input",
            Critical,
            r#"(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{(?:req\b|params\b|query\b|body\b|input\b|user)|['"][^'"]*\s*\+\s*(?:req\b|params\b|query\b|body\b|input\b|user))"#,
            JS_TS,
        ),
        (
            "cmd-injection-spawn",
            "Command injection - spawn with user input",
            High,
            r#"(?:spawn|spawnSync)\s*\(\s*(?:req\.|params\.|query\.|body\.)"#,
            JS_TS,
        ),
        (
            "cmd-injection-os-system",
            "Command injection - os.system with variable",
            Critical,
            r#"os\.system\s*\(\s*f['\"]"#,
            PY,
        ),
        (
            "cmd-injection-subprocess",
            "Command injection - subprocess with shell=True",
            High,
            r#"subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True"#,
            PY,
        ),
        (
            "cmd-injection-php",
            "Command injection - PHP exec/system/passthru",
            Critical,
            r#"(?:^|[^\w>:$])(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$"#,
            PHP,
        ),
        // Path Traversal
        (
            "path-traversal-join",
            "Path traversal - user input in file path",
            High,
            r#"(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\([^)]*(?:req\.|params\.|query\.|body\.)"#,
            JS_TS,
        ),
        (
            "path-traversal-open",
            "Path traversal - open() with user input",
            High,
            r#"open\s*\(\s*(?:request\.|f['"'])"#,
            PY,
        ),
        // Insecure Crypto
        (
            "insecure-crypto-md5",
            "Insecure hash - MD5",
            Medium,
            r#"(?:createHash|hashlib\.md5|MD5|md5)\s*\(\s*['"']?md5"#,
            ALL_WEB,
        ),
        (
            "insecure-crypto-sha1",
            "Insecure hash - SHA1",
            Medium,
            r#"(?:createHash|hashlib\.sha1|SHA1)\s*\(\s*['"']?sha1"#,
            ALL_WEB,
        ),
        (
            "insecure-crypto-des",
            "Insecure cipher - DES",
            High,
            r#"(?i)(?:createCipher(?:iv)?\s*\(\s*['"]des|des-(?:ecb|cbc|ede)|DESede|TripleDES|Blowfish)"#,
            ALL_WEB,
        ),
        (
            "insecure-crypto-ecb",
            "Insecure mode - ECB",
            High,
            r#"(?i)(?:aes[/-].*ecb|AES/ECB|mode\s*[:=]\s*['"]?ECB|createCipher(?:iv)?\s*\(\s*['"]aes-\d+-ecb)"#,
            ALL_WEB,
        ),
        (
            "insecure-random",
            "Insecure random - Math.random for security",
            High,
            r#"Math\.random\s*\(\s*\).*(?i)(?:token|secret|password|key|salt|nonce|iv|csrf)"#,
            JS_TS,
        ),
        // Open Redirect
        (
            "open-redirect",
            "Open redirect - unvalidated redirect",
            Medium,
            r#"(?:res\.redirect|redirect)\s*\(\s*(?:req\.|params\.|query\.)"#,
            JS_TS,
        ),
        // SSRF
        (
            "ssrf-fetch",
            "SSRF - fetch/request with user-controlled URL",
            High,
            r#"(?:fetch|axios\.get|https?\.get|got|request)\s*\(\s*(?:req\.|params\.|query\.|body\.)"#,
            JS_TS,
        ),
        (
            "ssrf-python",
            "SSRF - requests with user-controlled URL",
            High,
            r#"requests\.(?:get|post|put|delete)\s*\(\s*(?:request\.|f['"'])"#,
            PY,
        ),
        // Deserialization
        (
            "unsafe-deserialization-pickle",
            "Unsafe deserialization - pickle.loads",
            Critical,
            r#"pickle\.loads?\s*\("#,
            PY,
        ),
        (
            "unsafe-deserialization-yaml",
            "Unsafe deserialization - yaml.load without SafeLoader",
            High,
            r#"yaml\.load\s*\([^)]*\)"#,
            PY,
        ),
        (
            "unsafe-deserialization-php",
            "Unsafe deserialization - unserialize with user input",
            Critical,
            r#"unserialize\s*\(\s*\$"#,
            PHP,
        ),
        // Hardcoded Crypto
        (
            "hardcoded-iv",
            "Hardcoded initialization vector",
            Medium,
            r#"(?i)(?:iv|initialization.?vector)\s*[:=]\s*['"][^'"]{8,}['"]"#,
            ALL_WEB,
        ),
        (
            "hardcoded-salt",
            "Hardcoded salt value",
            Medium,
            r#"(?i)salt\s*[:=]\s*['"][^'"]{4,}['"]"#,
            ALL_WEB,
        ),
        // CORS
        (
            "cors-wildcard",
            "CORS wildcard - Access-Control-Allow-Origin: *",
            Medium,
            r#"(?i)access-control-allow-origin['":\s]*\*"#,
            ALL_WEB,
        ),
        // Prototype Pollution
        (
            "prototype-pollution",
            "Prototype pollution - __proto__ assignment",
            High,
            r#"__proto__\s*[=\[]"#,
            JS_TS,
        ),
        // NoSQL Injection
        (
            "nosql-injection",
            "NoSQL injection - operator from user input",
            High,
            r#"(?:\$where|\$gt|\$ne|\$regex)\s*:\s*(?:req\.|params\.|query\.|body\.)"#,
            JS_TS,
        ),
    ];

    defs.into_iter()
        .filter_map(|(id, desc, sev, pat, ext)| {
            Regex::new(pat).ok().map(|regex| SastRule {
                id,
                description: desc,
                severity: sev,
                regex,
                extensions: ext,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn php_cmd_rule() -> SastRule {
        sast_rules()
            .into_iter()
            .find(|r| r.id == "cmd-injection-php")
            .unwrap()
    }

    #[test]
    fn cmd_injection_php_flags_real_functions() {
        let re = php_cmd_rule().regex;
        for line in [
            "exec($cmd);",
            "    system($x);",
            "$out = shell_exec($y);",
            "if (\\exec($c)) {}",
            "passthru( $c );",
        ] {
            assert!(re.is_match(line), "should match: {line}");
        }
    }

    #[test]
    fn cmd_injection_php_ignores_lookalikes_and_methods() {
        let re = php_cmd_rule().regex;
        for line in [
            "$response = curl_exec($ch);",
            "fpassthru($stream);",
            "fpassthru($payload->stream);",
            "$pdo->exec($sql);",
            "Db::exec($sql);",
        ] {
            assert!(!re.is_match(line), "should not match: {line}");
        }
    }
}
