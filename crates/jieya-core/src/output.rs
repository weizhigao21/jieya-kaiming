use std::path::{Component, Path, PathBuf};

use crate::config::DEFAULT_ARCHIVE_EXTS;
use crate::detect::{volume_info, VIDEO_EXTS};

const ARCHIVE_SUFFIXES: &[&str] = DEFAULT_ARCHIVE_EXTS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// 解到压缩包旁边：`<源目录>/<包名>/`
    SameDir,
    /// 解到隔离工作目录，成功后复制回源目录
    Workdir,
}

#[derive(Debug, Clone, Default)]
pub struct OutputPlan {
    pub out_dir: PathBuf,
    pub final_dir: Option<PathBuf>,
    pub copy_back: bool,
    pub overwrite: bool,
    pub warnings: Vec<String>,
}

/// 目录名消毒：Windows 非法字符、结尾点/空格、保留设备名、`..` 逃逸
pub fn sanitize_component(name: &str) -> String {
    // 盘符逃逸（`C:`）要在字符替换之前判，否则冒号先被换成下划线就认不出来了
    if name.len() == 2 && name.ends_with(':') {
        return "output".to_string();
    }
    let mut cleaned: String = name
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();
    while cleaned.ends_with('.') || cleaned.ends_with(' ') {
        cleaned.pop();
    }
    while cleaned.starts_with(' ') {
        cleaned.remove(0);
    }
    let lower = cleaned.to_ascii_lowercase();
    let reserved = [
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
        "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." || reserved.contains(&lower.as_str()) {
        return "output".to_string();
    }
    // 盘符逃逸：`C:` 这类
    if cleaned.len() == 2 && cleaned.ends_with(':') {
        return "output".to_string();
    }
    cleaned
}

/// 压缩包路径 → 单层目录名：去掉压缩后缀、视频后缀与分卷标记
pub fn archive_dir_name(archive: &Path) -> String {
    // 分卷要用完整文件名做后续剥离（pack.7z.001 不能先当 stem 处理），
    // 其余一律从 stem 起步：伪装成 .dat 的包也去得掉那一层假后缀。
    let mut name = match volume_info(archive) {
        // 分卷直接用组标识（pack.part01.rar → pack.rar / pack.7z.001 → pack.7z）
        Some((base, _)) => base,
        None => match archive.file_stem() {
            Some(n) => n.to_string_lossy().to_string(),
            None => match archive.file_name() {
                Some(n) => n.to_string_lossy().to_string(),
                None => return "output".to_string(),
            },
        },
    };
    while std::path::Path::new(&name)
        .extension()
        .map(|e| {
            let ext = format!(".{}", e.to_string_lossy().to_ascii_lowercase());
            ARCHIVE_SUFFIXES.contains(&ext.as_str()) || VIDEO_EXTS.contains(&ext.as_str())
        })
        .unwrap_or(false)
    {
        match Path::new(&name).file_stem() {
            Some(stem) => name = stem.to_string_lossy().to_string(),
            None => break,
        }
    }
    sanitize_component(&name)
}

/// 不冲突的路径：目录 `pack` → `pack~2`；文件 `a.txt` → `a~2.txt`
pub fn unique_path(base: &Path) -> PathBuf {
    if !base.exists() {
        return base.to_path_buf();
    }
    let stem = base
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let ext = base
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let parent = base.parent().unwrap_or(Path::new("."));
    for i in 2..1000 {
        let cand = parent.join(format!("{stem}~{i}{ext}"));
        if !cand.exists() {
            return cand;
        }
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    parent.join(format!("{stem}~{stamp}{ext}"))
}

/// 是否同一卷：同卷才能 rename 代替整树复制。
///
/// 用盘符前缀做判据（`C:\` vs `F:\`）——std 在 Windows 上还没有稳定的卷序列号
/// 接口（`MetadataExt::volume_serial_number` 仍是 unstable feature）。
/// 网络盘 / subst 盘会被判成"不同卷"，退回复制只是慢一点，不会出错。
pub fn same_volume(a: &Path, b: &Path) -> bool {
    match (volume_key(a), volume_key(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

fn volume_key(path: &Path) -> Option<String> {
    let abs = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    for comp in abs.components() {
        if let Component::Prefix(prefix) = comp {
            let s = prefix.as_os_str().to_string_lossy().to_ascii_lowercase();
            return Some(s);
        }
    }
    None
}

pub const STAGING_DIR_NAME: &str = ".jieya_staging";

fn drive_root(path: &Path) -> Option<PathBuf> {
    let abs = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let mut comps = abs.components();
    match comps.next() {
        Some(Component::Prefix(prefix)) => {
            let p = PathBuf::from(prefix.as_os_str());
            let s = p.to_string_lossy().to_string();
            if s.len() == 2 && s.ends_with(':') {
                Some(PathBuf::from(format!("{s}\\")))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// 暂存区跟着产物落点走：跨卷时落到目标盘根下的固定目录
pub fn staging_root(base_workdir: &Path, anchor: &Path) -> PathBuf {
    if same_volume(base_workdir, anchor) {
        return base_workdir.to_path_buf();
    }
    match drive_root(anchor) {
        Some(root) => root.join(STAGING_DIR_NAME),
        None => base_workdir.to_path_buf(),
    }
}

/// 给一个任务算落点。
///
/// 不变式：`plan.out_dir` 的最后一段恒等于包名目录（见 [`archive_dir_name`]），
/// 内层包因此会在最终产物里留下一级目录，而不是被拍平。
pub fn plan_output(
    archive: &Path,
    depth: u32,
    task_id: u64,
    mode: OutputMode,
    workdir: &Path,
    parent_out: Option<&Path>,
    overwrite_existing: bool,
    target_dir: Option<&Path>,
) -> OutputPlan {
    let name = archive_dir_name(archive);

    // 嵌套任务永远是中间产物，落在父产物目录内
    if depth > 0 {
        let base = parent_out.map(|p| p.to_path_buf()).unwrap_or_else(|| workdir.to_path_buf());
        let out = unique_path(&base.join(&name));
        return OutputPlan {
            out_dir: out,
            final_dir: None,
            copy_back: false,
            overwrite: false,
            warnings: Vec::new(),
        };
    }

    // 显式指定了目标目录时，顶层产物直接落到目标目录下的包名子目录
    let anchor = target_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| archive.parent().unwrap_or(Path::new(".")).to_path_buf());
    match mode {
        OutputMode::SameDir => {
            let base = anchor.join(&name);
            if overwrite_existing && base.is_dir() {
                return OutputPlan {
                    out_dir: base.clone(),
                    final_dir: Some(base),
                    copy_back: false,
                    overwrite: true,
                    warnings: Vec::new(),
                };
            }
            let final_dir = unique_path(&base);
            OutputPlan {
                out_dir: final_dir.clone(),
                final_dir: Some(final_dir),
                copy_back: false,
                overwrite: false,
                warnings: Vec::new(),
            }
        }
        OutputMode::Workdir => {
            let out_dir = workdir.join(format!("task_{task_id}")).join("out").join(&name);
            let final_dir = unique_path(&anchor.join(&name));
            OutputPlan {
                out_dir,
                final_dir: Some(final_dir),
                copy_back: true,
                overwrite: false,
                warnings: Vec::new(),
            }
        }
    }
}
