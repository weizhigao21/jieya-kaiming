use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// (偏移, magic, 类型名)，与 Python 版 _MAGIC_HEADERS 一致
const MAGIC_HEADERS: &[(u64, &[u8], &str)] = &[
    (0, b"PK\x03\x04", "zip"),
    (0, b"PK\x05\x06", "zip"),
    (0, b"PK\x07\x08", "zip"),
    (0, b"Rar!\x1a\x07", "rar"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z"),
    (0, b"\x1f\x8b", "gzip"),
    (0, b"BZh", "bzip2"),
    (0, b"\xfd7zXZ\x00", "xz"),
    (0, b"MSCF", "cab"),
    (0, b"MSWIM\x00\x00\x00", "wim"),
    (0, b"WLPWM\x00\x00\x00", "wim"),
    (257, b"ustar", "tar"),
];

const ISO_OFFSET: u64 = 0x8001;
const ISO_MAGIC: &[u8] = b"CD001";

pub const VIDEO_EXTS: &[&str] = &[
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".mpg", ".mpeg",
];

/// 已知「不可能是压缩包」的扩展名：命中即判否，不读文件头（省掉几万次 open）
pub const NOT_ARCHIVE_EXTS: &[&str] = &[
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".ico", ".svg", ".avif",
    ".heic", ".psd", ".mp3", ".flac", ".wav", ".aac", ".ogg", ".m4a", ".wma", ".ape", ".txt",
    ".md", ".nfo", ".log", ".json", ".xml", ".csv", ".tsv", ".ini", ".cfg", ".yaml", ".yml",
    ".toml", ".pdf", ".rtf", ".srt", ".ass", ".vtt", ".ttf", ".otf", ".woff", ".woff2",
];

/// 本质是 zip 的应用文档/安装包，不展开
pub const COMPOUND_ZIP_EXTS: &[&str] = &[
    ".docx", ".docm", ".xlsx", ".xlsm", ".xltx", ".xltm", ".pptx", ".pptm", ".potx", ".potm",
    ".odt", ".ods", ".odp", ".epub", ".jar", ".apk", ".ipa", ".xapk", ".vsix", ".whl", ".appx",
    ".msix",
];

fn ext_lower(path: &Path) -> String {
    path.extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_ascii_lowercase()))
        .unwrap_or_default()
}

/// 识别分卷文件，返回 (同组标识, 分卷序号)。同组标识不含目录。
pub fn volume_info(path: &Path) -> Option<(String, u32)> {
    let name = path.file_name()?.to_string_lossy().to_string();
    if let Some(v) = parse_part_style(&name) {
        return Some(v);
    }
    parse_split_style(&name)
}

fn archive_ext_ok(ext: &str) -> bool {
    matches!(ext.to_ascii_lowercase().as_str(), "rar" | "zip" | "7z")
}

/// a.part01.rar / a.part1.rar
fn parse_part_style(name: &str) -> Option<(String, u32)> {
    let lower = name.to_ascii_lowercase();
    let idx = lower.rfind(".part")?;
    let rest = &lower[idx + 5..];
    let digits_len = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits_len == 0 {
        return None;
    }
    let num: u32 = rest[..digits_len].parse().ok()?;
    let after = &rest[digits_len..];
    let ext = after.strip_prefix('.')?;
    if !archive_ext_ok(ext) {
        return None;
    }
    let base = name[..idx].to_string();
    Some((format!("{}.{}", base.to_ascii_lowercase(), ext), num))
}

/// a.7z.001 / a.zip.002 / a.rar.003
fn parse_split_style(name: &str) -> Option<(String, u32)> {
    let (head, tail) = name.rsplit_once('.')?;
    if !(3..=4).contains(&tail.len()) || !tail.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let (base, ext) = head.rsplit_once('.')?;
    if !archive_ext_ok(ext) {
        return None;
    }
    let num: u32 = tail.parse().ok()?;
    Some((format!("{}.{}", base.to_ascii_lowercase(), ext.to_ascii_lowercase()), num))
}

/// 整组分卷的 (总字节数, 卷数)；非分卷返回 (自身大小, 1)。
pub fn volume_group_total(path: &Path) -> (u64, usize) {
    let own = path.metadata().map(|m| m.len()).unwrap_or(0);
    let Some((base, _)) = volume_info(path) else {
        return (own, 1);
    };
    let Some(parent) = path.parent() else {
        return (own, 1);
    };
    let mut total = 0u64;
    let mut count = 0usize;
    if let Ok(entries) = std::fs::read_dir(parent) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Some((other, _)) = volume_info(&p) {
                if other == base && p.is_file() {
                    if let Ok(meta) = p.metadata() {
                        total += meta.len();
                        count += 1;
                    }
                }
            }
        }
    }
    if count == 0 {
        (own, 1)
    } else {
        (total, count)
    }
}

fn read_head(path: &Path, size: u64) -> Option<Vec<u8>> {
    if size < 8 {
        return None;
    }
    let mut f = File::open(path).ok()?;
    let mut head = vec![0u8; 4096];
    let n = f.read(&mut head).ok()?;
    head.truncate(n);
    Some(head)
}

/// 读文件头识别压缩包，返回 (文件大小, 类型名)；识别不出类型名为空。
fn sniff(path: &Path) -> (u64, String) {
    let Ok(meta) = path.metadata() else {
        return (0, String::new());
    };
    let size = meta.len();
    let Some(head) = read_head(path, size) else {
        return (size, String::new());
    };
    for (offset, magic, name) in MAGIC_HEADERS {
        let start = *offset as usize;
        let end = start + magic.len();
        if head.len() >= end && &head[start..end] == *magic {
            return (size, (*name).to_string());
        }
    }
    if size >= ISO_OFFSET + 5 {
        if let Ok(mut f) = File::open(path) {
            if f.seek(SeekFrom::Start(ISO_OFFSET)).is_ok() {
                let mut buf = [0u8; 5];
                if f.read_exact(&mut buf).is_ok() && buf == ISO_MAGIC {
                    return (size, "iso".to_string());
                }
            }
        }
    }
    (size, String::new())
}

/// 视频载体中的内嵌 zip（真正的尾部 EOCD 扫描在 embedded.rs）
pub fn find_embedded_zip(path: &Path) -> Option<EmbeddedZipInfo> {
    crate::embedded::find_embedded_zip(path).map(|z| EmbeddedZipInfo {
        start: z.start,
        end: z.end,
    })
}

#[derive(Debug, Clone)]
pub struct EmbeddedZipInfo {
    pub start: u64,
    pub end: u64,
}

pub fn sniff_format(path: &Path) -> String {
    let ext = ext_lower(path);
    if VIDEO_EXTS.contains(&ext.as_str()) {
        if find_embedded_zip(path).is_some() {
            return "zip".to_string();
        }
        return sniff(path).1;
    }
    if NOT_ARCHIVE_EXTS.contains(&ext.as_str()) {
        return String::new();
    }
    sniff(path).1
}

pub fn looks_like_archive(path: &Path) -> bool {
    let ext = ext_lower(path);
    if VIDEO_EXTS.contains(&ext.as_str()) {
        return find_embedded_zip(path).is_some() || !sniff(path).1.is_empty();
    }
    if NOT_ARCHIVE_EXTS.contains(&ext.as_str()) {
        return false;
    }
    !sniff(path).1.is_empty() || find_embedded_zip(path).is_some()
}

/// 候选输入：目录递归展开，压缩包先按 magic 判定
pub fn collect_inputs(inputs: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for input in inputs {
        if input.is_dir() {
            for f in crate::walk::iter_files(input) {
                if looks_like_archive(&f) {
                    out.push(f);
                }
            }
        } else if input.is_file() {
            out.push(input.clone());
        }
    }
    out
}
