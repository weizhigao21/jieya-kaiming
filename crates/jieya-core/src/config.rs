use std::env;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

pub const DEFAULT_ARCHIVE_EXTS: &[&str] = &[
    ".zip", ".rar", ".7z", ".cbz", ".cbr", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso", ".001",
];

const GIB: u64 = 1024 * 1024 * 1024;

/// 定位 7z.exe：显式参数 > SEVENZIP_PATH > 常见安装路径 > PATH。
pub fn detect_sevenzip(explicit: Option<&str>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Ok(pb);
        }
        return Err(Error::Config(format!("指定的 7z 不存在: {}", pb.display())));
    }
    if let Ok(env_path) = env::var("SEVENZIP_PATH") {
        let pb = PathBuf::from(env_path);
        if pb.is_file() {
            return Ok(pb);
        }
    }
    let pf = env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
    let pf86 =
        env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".into());
    for base in [pf, pf86] {
        let pb = Path::new(&base).join("7-Zip").join("7z.exe");
        if pb.is_file() {
            return Ok(pb);
        }
    }
    for dir in env::split_paths(&env::var("PATH").unwrap_or_default()) {
        let pb = dir.join("7z.exe");
        if pb.is_file() {
            return Ok(pb);
        }
        let pb_np = dir.join("7z");
        if pb_np.is_file() {
            return Ok(pb_np);
        }
    }
    Err(Error::Config(
        "未找到 7z.exe：请安装 7-Zip，或设置环境变量 SEVENZIP_PATH，或传 --sevenzip".into(),
    ))
}

#[derive(Debug, Clone)]
pub struct Config {
    pub sevenzip_path: PathBuf,
    pub workdir: PathBuf,
    pub vault_path: PathBuf,
    pub max_depth: u32,
    pub max_total_uncompressed: u64,
    pub max_compression_ratio: f64,
    pub ratio_floor_bytes: u64,
    pub max_password_attempts: usize,
    pub delete_intermediate: bool,
    pub keep_original: bool,
    pub sniff_archives: bool,
    pub overwrite_existing: bool,
    pub skip_done: bool,
    pub list_timeout_secs: u64,
    pub extract_timeout_secs: u64,
    pub cloud_unlock: bool,
    pub cloud_unlock_timeout_secs: u64,
    pub cloud_unlock_udid: String,
}

impl Config {
    pub fn create(sevenzip: Option<&str>, workdir: Option<&Path>) -> Result<Self> {
        Ok(Self {
            sevenzip_path: detect_sevenzip(sevenzip)?,
            workdir: workdir
                .map(|p| p.to_path_buf())
                .unwrap_or_else(default_workdir),
            vault_path: crate::vault::Vault::default_path(),
            max_depth: 5,
            max_total_uncompressed: 50 * GIB,
            max_compression_ratio: 1000.0,
            ratio_floor_bytes: GIB,
            max_password_attempts: 20,
            delete_intermediate: true,
            keep_original: true,
            sniff_archives: true,
            overwrite_existing: false,
            // 与 CLI 行为一致：默认重解一遍，避免用户改过密码库后旧记录挡住
            skip_done: false,
            list_timeout_secs: 120,
            extract_timeout_secs: 3600,
            cloud_unlock: false,
            cloud_unlock_timeout_secs: 10,
            cloud_unlock_udid: String::new(),
        })
    }

    pub fn archive_ext(&self, ext: &str) -> bool {
        let lower = ext.to_ascii_lowercase();
        DEFAULT_ARCHIVE_EXTS.contains(&lower.as_str())
    }
}

fn default_workdir() -> PathBuf {
    env::var("LOCALAPPDATA")
        .map(|p| PathBuf::from(p).join("解压开镜").join(".workspace"))
        .unwrap_or_else(|_| env::temp_dir().join("jieya_workspace"))
}
