use std::path::Path;

use crate::config::Config;
use crate::detect::{sniff_format, volume_group_total, volume_info};
use crate::error::{Error, Result};
use crate::models::{ArchiveEntry, ArchiveInfo};
use crate::sevenzip::SevenZip;

const WRONG_PW_MARKERS: &[&str] = &[
    "wrong password",
    "错误的密码",
    "密码错误",
    "密码不正确",
];
const NEEDS_PW_MARKERS: &[&str] = &["break signaled", "中断信号"];

/// 分卷容器名的 Type 不是「格式」
const NOT_A_FORMAT: &[&str] = &["", "split"];

/// 解析 `7z l -slt` 输出，只统计分隔线之后的条目块。
pub fn parse_slt(text: &str, archive: &Path) -> ArchiveInfo {
    let mut info = ArchiveInfo {
        path: archive.to_path_buf(),
        format_name: pick_format(text),
        ..Default::default()
    };
    let (size, count) = volume_group_total(archive);
    info.archive_size = size;
    info.volume_count = count;

    let mut started = false;
    let mut entry: Option<ArchiveEntry> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if !started {
            if trimmed.len() >= 5 && trimmed.chars().all(|c| c == '-') {
                started = true;
            }
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key == "Path" {
            if let Some(e) = entry.take() {
                consume(&mut info, e);
            }
            entry = Some(ArchiveEntry {
                path: value.to_string(),
                ..Default::default()
            });
        } else if let Some(e) = entry.as_mut() {
            match key {
                "Size" => e.size = value.parse().unwrap_or(0),
                "Folder" => e.is_dir = value == "+",
                "Encrypted" => {
                    if matches!(value.to_ascii_lowercase().as_str(), "+" | "true" | "yes") {
                        info.flag_encrypted = true;
                    }
                }
                _ => {}
            }
        }
    }
    if let Some(e) = entry.take() {
        consume(&mut info, e);
    }
    info
}

fn consume(info: &mut ArchiveInfo, entry: ArchiveEntry) {
    if entry.is_dir {
        info.dir_count += 1;
    } else {
        info.file_count += 1;
        info.total_uncompressed += entry.size;
    }
    info.entries.push(entry);
}

/// 从 `l -slt` 里挑真实格式：分卷包会先报 Split 再报 zip
fn pick_format(text: &str) -> String {
    let mut found: Vec<String> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("Type =") {
            found.push(rest.trim().to_string());
        }
    }
    for name in &found {
        if !NOT_A_FORMAT.contains(&name.to_ascii_lowercase().as_str()) {
            return name.clone();
        }
    }
    found.first().cloned().unwrap_or_default()
}

fn with_format(mut info: ArchiveInfo, archive: &Path) -> ArchiveInfo {
    if NOT_A_FORMAT.contains(&info.format_name.trim().to_ascii_lowercase().as_str()) {
        let sniffed = sniff_format(archive);
        if !sniffed.is_empty() {
            info.format_name = sniffed;
        }
    }
    info
}

/// 空密码列目录：成功 → 解析；密码错误 → 头加密；其他 → 坏包。
pub fn probe(sz: &SevenZip, archive: &Path) -> Result<ArchiveInfo> {
    let (code, out, err) = sz.list_raw(archive, "")?;
    if code == 0 {
        return Ok(with_format(parse_slt(&out, archive), archive));
    }
    let text = format!("{out}{err}");
    let low = text.to_ascii_lowercase();
    if WRONG_PW_MARKERS.iter().any(|m| low.contains(m) || text.contains(m)) {
        let mut info = ArchiveInfo {
            path: archive.to_path_buf(),
            needs_password_for_listing: true,
            ..Default::default()
        };
        let (size, count) = volume_group_total(archive);
        info.archive_size = size;
        info.volume_count = count;
        return Ok(with_format(info, archive));
    }
    Err(Error::Probe(truncate_tail(&text, 400)))
}

/// 用已知密码复探加密包，补上真实的解压后总大小
pub fn probe_with_password(sz: &SevenZip, archive: &Path, password: &str) -> Result<Option<ArchiveInfo>> {
    let (code, out, _err) = sz.list_raw(archive, password)?;
    if code != 0 {
        return Ok(None);
    }
    Ok(Some(with_format(parse_slt(&out, archive), archive)))
}

/// zip bomb 检查，返回拒绝原因；None 表示通过。
pub fn check_bomb(info: &ArchiveInfo, cfg: &Config) -> Option<String> {
    const GIB: u64 = 1024 * 1024 * 1024;
    if info.total_uncompressed > cfg.max_total_uncompressed {
        return Some(format!(
            "疑似 zip bomb：解压后总大小 {:.1} GiB 超过上限 {:.1} GiB",
            info.total_uncompressed as f64 / GIB as f64,
            cfg.max_total_uncompressed as f64 / GIB as f64
        ));
    }
    if info.archive_size > 0
        && info.total_uncompressed > cfg.ratio_floor_bytes
        && info.compression_ratio() > cfg.max_compression_ratio
    {
        return Some(format!(
            "疑似 zip bomb：压缩比 {:.0}:1 超过上限 {:.0}:1",
            info.compression_ratio(),
            cfg.max_compression_ratio
        ));
    }
    None
}

/// 解压结果分类：返回 (成功?, 是否密码问题, 消息)
pub fn classify_extract(exit_code: i32, text: &str) -> (bool, bool, String) {
    if exit_code == 0 {
        return (true, false, String::new());
    }
    let low = text.to_ascii_lowercase();
    let wrong_pw = WRONG_PW_MARKERS.iter().any(|m| low.contains(m) || text.contains(m))
        || NEEDS_PW_MARKERS.iter().any(|m| low.contains(m) || text.contains(m));
    let msg = {
        let t = text.trim();
        if t.is_empty() {
            format!("7z 退出码 {exit_code}")
        } else {
            truncate_tail(t, 400)
        }
    };
    (false, wrong_pw, msg)
}

fn truncate_tail(s: &str, max_chars: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max_chars {
        return s.trim().to_string();
    }
    chars[chars.len() - max_chars..].iter().collect::<String>().trim().to_string()
}

/// 这个文件是不是分卷的非首卷（只解首卷）
pub fn is_non_first_volume(path: &Path) -> bool {
    matches!(volume_info(path), Some((_, n)) if n > 1)
}
