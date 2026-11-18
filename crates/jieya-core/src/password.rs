//! 密码候选现场提取：文件名/注释提示 → 来源域名派生 → 密码库 → 内置字典。
//!
//! 手写扫描而不是上 regex：这个项目对体积敏感，几条固定规则不值得多带一个
//! 正则引擎；规则本身也和原版 `password_finder.py` 逐条对齐。

pub const BUILTIN_DICT: &[&str] = &[
    "123456", "1234", "12345678", "1234567890", "password", "admin", "88888888", "66666666",
];

const KEYWORDS: &[&str] = &["密码", "密碼", "password", "passwd", "pw", "pass"];

const TLDS: &[&str] = &[
    "com", "net", "org", "cc", "me", "xyz", "top", "vip", "club", "info", "io", "cn", "tv", "us",
    "co", "la", "moe", "fun", "site", "shop", "link", "icu", "biz", "asia",
];

fn is_open_bracket(c: char) -> bool {
    matches!(c, '[' | '【' | '（' | '(')
}

fn is_close_bracket(c: char) -> bool {
    matches!(c, ']' | '】' | '）' | ')')
}

/// 括号内是不是「密码:xxx」形式；是则返回密码部分
fn password_in_bracket(content: &str) -> Option<String> {
    let trimmed = content.trim();
    let lower = trimmed.to_ascii_lowercase();
    let (kw, rest) = KEYWORDS
        .iter()
        .filter_map(|kw| {
            if lower.starts_with(&kw.to_ascii_lowercase()) {
                // 关键词字面与 lower 的 UTF-8 字节长度一致（中文不受 case 折叠影响）
                let tail = trimmed.get(kw.len()..)?;
                Some((*kw, tail))
            } else {
                None
            }
        })
        .max_by_key(|(kw, _)| kw.len())?;
    let _ = kw;
    let rest = rest.trim_start();
    let value = rest
        .trim_start_matches([':', '：', '='])
        .trim()
        .trim_matches(|c: char| matches!(c, '。' | '.' | ',' | '，' | '、' | ' '));
    if value.is_empty() || value.chars().count() > 64 {
        return None;
    }
    Some(value.to_string())
}

/// 文件名里的密码提示：`[密码:xxx]`、`（密码：xxx）`、`password:xxx`
pub fn extract_passwords_from_name(name: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut push = |pwd: String| {
        if !pwd.is_empty() && !found.iter().any(|p| *p == pwd) {
            found.push(pwd);
        }
    };

    // ① 括号形式：逐个括号取内容
    let mut open: Option<usize> = None;
    for (idx, ch) in name.char_indices() {
        if open.is_none() && is_open_bracket(ch) {
            open = Some(idx + ch.len_utf8());
        } else if let Some(start) = open {
            if is_close_bracket(ch) {
                let content = &name[start..idx];
                if let Some(pwd) = password_in_bracket(content) {
                    push(pwd);
                }
                open = None;
            }
        }
    }

    // ② 裸形式：关键词 + 冒号/等号 + 允许的字符集
    let lower = name.to_ascii_lowercase();
    for kw in KEYWORDS {
        let kw_l = kw.to_ascii_lowercase();
        let mut from = 0usize;
        while let Some(pos) = lower[from..].find(&kw_l) {
            let abs = from + pos;
            // 按字节推进（keyword 原文与 lower 的字节长度一致）
            let after_kw = (abs + kw_l.len()).min(name.len());
            let tail = &name[after_kw..];
            let tail = tail.trim_start();
            if let Some(stripped) = tail.strip_prefix([':', '：', '=']) {
                let token: String = stripped
                    .trim_start()
                    .chars()
                    .take_while(|c| {
                        c.is_ascii_alphanumeric()
                            || matches!(c, '@' | '#' | '$' | '_' | '&' | '+' | '-' | '.' | '~' | '^')
                    })
                    .collect();
                // `password:xk9-2024.zip` 里的 `.zip` 是文件后缀，不属于密码
                let token = strip_archive_ext(token);
                if (3..=64).contains(&token.chars().count()) {
                    push(token);
                }
            }
            from = abs + kw_l.len();
            if from >= lower.len() {
                break;
            }
        }
    }
    found
}

fn strip_archive_ext(mut token: String) -> String {
    let lower = token.to_ascii_lowercase();
    for ext in [
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso", ".001", ".cbz", ".cbr",
    ] {
        if lower.ends_with(ext) {
            token.truncate(token.len() - ext.len());
            break;
        }
    }
    token
}

fn valid_domain(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    let Some((_, tld)) = lower.rsplit_once('.') else {
        return false;
    };
    if !TLDS.contains(&tld) {
        return false;
    }
    lower
        .split('.')
        .all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && label.starts_with(|c: char| c.is_ascii_alphanumeric())
                && label.ends_with(|c: char| c.is_ascii_alphanumeric())
        })
}

/// 从文件名提取来源域名：优先括号内的完整域名，兜底宽松匹配
pub fn extract_source(name: &str) -> String {
    // ① 括号内完整域名
    let mut open: Option<usize> = None;
    for (idx, ch) in name.char_indices() {
        if open.is_none() && is_open_bracket(ch) {
            open = Some(idx + ch.len_utf8());
        } else if let Some(start) = open {
            if is_close_bracket(ch) {
                let content = name[start..idx].trim();
                if valid_domain(content) {
                    return content.to_ascii_lowercase();
                }
                open = None;
            }
        }
    }
    // ② 全文里出现的第一段「域名形状」子串
    let mut candidate = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' {
            candidate.push(ch);
        } else {
            if valid_domain(&candidate) {
                return candidate.to_ascii_lowercase();
            }
            candidate.clear();
        }
    }
    if valid_domain(&candidate) {
        return candidate.to_ascii_lowercase();
    }
    String::new()
}

/// 很多站点直接拿域名当密码
pub fn derived_from_source(source: &str) -> Vec<String> {
    if source.is_empty() {
        return Vec::new();
    }
    vec![source.to_string(), format!("www.{source}")]
}

/// 按优先级合并候选：文件名提示 → 来源派生 → 密码库 → 内置字典
pub fn build_candidates(archive_name: &str, source: &str, vault: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |pwd: &str| {
        if !pwd.is_empty() && !out.iter().any(|p| p == pwd) {
            out.push(pwd.to_string());
        }
    };
    for pwd in extract_passwords_from_name(archive_name) {
        add(&pwd);
    }
    for pwd in derived_from_source(source) {
        add(&pwd);
    }
    for pwd in vault {
        add(pwd);
    }
    for pwd in BUILTIN_DICT {
        add(pwd);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bracket_password() {
        let got = extract_passwords_from_name("资源包[密码:abc123].zip");
        assert_eq!(got, vec!["abc123"]);
        let got = extract_passwords_from_name("【密码：中文密码】合集.7z");
        assert_eq!(got, vec!["中文密码"]);
    }

    #[test]
    fn bare_password() {
        let got = extract_passwords_from_name("合集 password:xk9-2024.zip");
        assert_eq!(got, vec!["xk9-2024"]);
        // 太短的不算
        assert!(extract_passwords_from_name("pw:12.zip").is_empty());
    }

    #[test]
    fn source_domain() {
        assert_eq!(extract_source("[moe123.net]资源包.zip"), "moe123.net");
        assert_eq!(extract_source("某站 www.abc.com 资源.zip"), "www.abc.com");
        assert_eq!(extract_source("没有域名的包.zip"), "");
    }

    #[test]
    fn candidates_order() {
        let got = build_candidates("[密码:p1]资源[a.com].zip", "a.com", &["v1".into()]);
        assert_eq!(got[0], "p1");
        assert_eq!(got[1], "a.com");
        assert_eq!(got[2], "www.a.com");
        assert_eq!(got[3], "v1");
        assert_eq!(got.len(), 4 + BUILTIN_DICT.len());
    }
}
