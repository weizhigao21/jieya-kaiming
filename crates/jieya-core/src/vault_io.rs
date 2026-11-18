//! 密码库的加密导出 / 导入（与 Python 版 `core/vault_export.py` 同格式）。
//!
//! 只做「库 ↔ 容器」的搬运，加密细节在 `bundle.rs`。明文只在内存里出现。

use std::path::{Path, PathBuf};

use chrono::Local;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::bundle::{self, BundleError, DEFAULT_N_LOG2};
use crate::error::{Error, Result};
use crate::vault::Vault;

pub const KIND: &str = "jieya-kaijing-vault";
pub const FORMAT_VERSION: u32 = 1;
pub const DEFAULT_DIRNAME: &str = "vault";

const MAX_ENTRIES: usize = 20_000;
const MAX_PASSWORD_LEN: usize = 512;
const MAX_SOURCE_LEN: usize = 200;

#[derive(Debug, Clone)]
pub struct ExportResult {
    pub path: PathBuf,
    pub entries: usize,
    pub plaintext_bytes: usize,
    pub bundle_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct ImportResult {
    pub path: PathBuf,
    pub added: usize,
    pub merged: usize,
    pub total: usize,
    pub exported_at: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Payload {
    app: String,
    kind: String,
    version: u32,
    exported_at: String,
    entries: Vec<PayloadEntry>,
}

#[derive(Serialize, Deserialize)]
struct PayloadEntry {
    password: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    hit_count: i64,
    #[serde(default)]
    last_hit_at: Option<String>,
}

fn transfer_err(msg: impl Into<String>) -> Error {
    Error::Other(msg.into())
}

/// `<base>/vault/passwords-YYYY-MM-DD.vault`
pub fn default_export_path(base: &Path) -> PathBuf {
    let stamp = Local::now().format("%Y-%m-%d");
    base.join(DEFAULT_DIRNAME)
        .join(format!("passwords-{stamp}.vault"))
}

pub fn export_vault(
    vault: &Vault,
    dest: &Path,
    password: &str,
    n_log2: u8,
) -> Result<ExportResult> {
    if password.is_empty() {
        return Err(transfer_err("口令不能为空"));
    }
    let entries = vault.list_all()?;
    let payload = Payload {
        app: "解压开镜".into(),
        kind: KIND.into(),
        version: FORMAT_VERSION,
        exported_at: Local::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
        entries: entries
            .iter()
            .map(|e| PayloadEntry {
                password: e.password.clone(),
                source: e.source.clone(),
                hit_count: e.hit_count,
                last_hit_at: e.last_hit_at.clone(),
            })
            .collect(),
    };
    let raw = serde_json::to_vec_pretty(&payload)
        .map_err(|e| transfer_err(format!("序列化失败: {e}")))?;
    let blob = bundle::seal(&raw, password, n_log2).map_err(bundle_err)?;

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // 先写临时文件再 rename：导出一半被关掉，原文件不会被截成半个
    let tmp = dest.with_file_name(format!(
        "{}.tmp",
        dest.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()
    ));
    std::fs::write(&tmp, &blob)?;
    if std::fs::rename(&tmp, dest).is_err() {
        std::fs::copy(&tmp, dest)?;
        let _ = std::fs::remove_file(&tmp);
    }

    Ok(ExportResult {
        path: dest.to_path_buf(),
        entries: payload.entries.len(),
        plaintext_bytes: raw.len(),
        bundle_bytes: blob.len(),
    })
}

fn bundle_err(e: BundleError) -> Error {
    match e {
        BundleError::EmptyPassword => transfer_err("口令不能为空"),
        other => transfer_err(other.to_string()),
    }
}

fn validated_entries(payload: &Value) -> Result<Vec<(String, String, i64, Option<String>)>> {
    let obj = payload
        .as_object()
        .ok_or_else(|| transfer_err("备份内容不是有效的密码库数据"))?;
    if obj.get("kind").and_then(|v| v.as_str()) != Some(KIND) {
        return Err(transfer_err("这不是解压开镜的密码库备份"));
    }
    let version = obj.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    if version != FORMAT_VERSION as u64 {
        return Err(transfer_err(format!(
            "备份的格式版本是 {version}，当前程序只认 {FORMAT_VERSION}"
        )));
    }
    let raw_entries = obj
        .get("entries")
        .and_then(|v| v.as_array())
        .ok_or_else(|| transfer_err("备份里没有密码条目"))?;
    if raw_entries.len() > MAX_ENTRIES {
        return Err(transfer_err(format!(
            "备份里有 {} 条密码，超过上限 {MAX_ENTRIES}；请确认这是你自己的密码库备份",
            raw_entries.len()
        )));
    }

    let mut rows = Vec::with_capacity(raw_entries.len());
    for (index, item) in raw_entries.iter().enumerate() {
        let index = index + 1;
        let item = item
            .as_object()
            .ok_or_else(|| transfer_err(format!("第 {index} 条记录格式不对")))?;
        let password = item
            .get("password")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| transfer_err(format!("第 {index} 条记录没有密码")))?;
        if password.chars().count() > MAX_PASSWORD_LEN {
            return Err(transfer_err(format!(
                "第 {index} 条密码过长（超过 {MAX_PASSWORD_LEN} 字符）"
            )));
        }
        let source = item.get("source").and_then(|v| v.as_str()).unwrap_or("");
        if source.chars().count() > MAX_SOURCE_LEN {
            return Err(transfer_err(format!("第 {index} 条来源过长")));
        }
        let hit_count = match item.get("hit_count") {
            None | Some(Value::Null) => 0,
            Some(v) => v
                .as_i64()
                .filter(|n| *n >= 0)
                .ok_or_else(|| transfer_err(format!("第 {index} 条记录的命中次数非法")))?,
        };
        let last_hit_at = match item.get("last_hit_at") {
            None | Some(Value::Null) => None,
            Some(v) => Some(
                v.as_str()
                    .ok_or_else(|| transfer_err(format!("第 {index} 条的最后命中时间非法")))?
                    .to_string(),
            ),
        };
        rows.push((password.to_string(), source.to_string(), hit_count, last_hit_at));
    }
    Ok(rows)
}

/// 解开容器字节，返回 `(条目, exported_at)`。不落盘、不合并。
pub fn read_bundle_entries(
    blob: &[u8],
    password: &str,
) -> Result<(Vec<(String, String, i64, Option<String>)>, Option<String>)> {
    if password.is_empty() {
        return Err(transfer_err("口令不能为空"));
    }
    if blob.is_empty() {
        return Err(transfer_err("备份文件是空的"));
    }
    bundle::inspect(blob).map_err(bundle_err)?;
    let raw = bundle::unseal(blob, password).map_err(bundle_err)?;
    let payload: Value = serde_json::from_slice(&raw)
        .map_err(|_| transfer_err("备份内容已损坏（不是有效的 JSON）"))?;
    let rows = validated_entries(&payload)?;
    let exported_at = payload
        .get("exported_at")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    Ok((rows, exported_at))
}

pub fn import_vault(vault: &Vault, src: &Path, password: &str) -> Result<ImportResult> {
    if password.is_empty() {
        return Err(transfer_err("口令不能为空"));
    }
    let blob = std::fs::read(src)
        .map_err(|e| transfer_err(format!("读不到备份文件：{e}")))?;
    let (rows, exported_at) = read_bundle_entries(&blob, password)?;
    let total = rows.len();
    let (added, merged) = vault.import_entries(&rows)?;
    Ok(ImportResult {
        path: src.to_path_buf(),
        added,
        merged,
        total,
        exported_at,
    })
}

#[allow(dead_code)]
pub const DEFAULT_N: u8 = DEFAULT_N_LOG2;
