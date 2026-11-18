//! 隔离工作目录的残留盘点与安全清理。
//!
//! 三类东西会在工作目录里无限堆积：交付失败留下的整份副本、跨卷交付时故意留着
//! 当安全网的副本、运行中途被杀留下的整层产物。它们全都是「解压成功」的状态，
//! 库里 done、界面显示完成，用户没有任何入口知道磁盘被吃了多少。
//!
//! 判定原则：**只把「已经确认交付过」的目录算作可清理**。产物还留在工作目录、
//! 任务没结束、库里查不到记录的，一律标记保留并写明原因——那可能是用户唯一的
//! 副本。清理永远由调用方显式触发，本模块不做任何自动删除。
//!
//! 三道闸：必须是已认领暂存根的直属 `task_<数字>` 子目录；目录本身不能是符号
//! 链接/junction；默认只删 safe 的项。

use std::path::{Path, PathBuf};

use crate::models::TaskStatus;
use crate::output::STAGING_DIR_NAME;
use crate::store::{StoredTask, TaskStore};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeftoverKind {
    /// 产物已确认交付到工作目录之外，这里这份是副本
    Cleanable,
    /// 产物就这一个副本，删了就真没了
    NotDelivered,
    /// 任务没成功结束（待密码/失败/迁移中）
    Unfinished,
    /// 库里有不认识的目录（换过库、库被清空过）
    Orphan,
}

impl LeftoverKind {
    pub fn label(self) -> &'static str {
        match self {
            LeftoverKind::Cleanable => "可清理",
            LeftoverKind::NotDelivered => "请保留",
            LeftoverKind::Unfinished => "请保留",
            LeftoverKind::Orphan => "待确认",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Leftover {
    pub path: PathBuf,
    pub task_id: Option<i64>,
    pub kind: LeftoverKind,
    pub reason: String,
    pub size: u64,
    pub files: usize,
    pub mtime: Option<std::time::SystemTime>,
}

impl Leftover {
    /// 产物已另有一份、这份纯属冗余——可以默认勾选清理。
    pub fn safe(&self) -> bool {
        self.kind == LeftoverKind::Cleanable
    }
}

fn task_id_of(path: &Path) -> Option<i64> {
    let name = path.file_name()?.to_str()?;
    let rest = name.strip_prefix("task_")?;
    if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
}

/// 是否是我们自己建的「盘根暂存区」——只认 `<盘符>:\.jieya_staging`。
///
/// 认得太宽很危险：任何同名目录都会被当成可删范围，所以只接受盘符根下那一个。
pub fn is_staging_root(path: &Path) -> bool {
    let Ok(p) = std::fs::canonicalize(path) else {
        return false;
    };
    let Some(name) = p.file_name() else {
        return false;
    };
    if !name.to_string_lossy().eq_ignore_ascii_case(STAGING_DIR_NAME) {
        return false;
    }
    // 父目录必须是盘根（再上一层没有父）
    match p.parent() {
        Some(parent) => parent.parent().is_none() && p.has_root(),
        None => false,
    }
}

#[cfg(windows)]
fn local_drives() -> Vec<char> {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetLogicalDrives() -> u32;
        fn GetDriveTypeW(lp_root_path_name: *const u16) -> u32;
    }
    // 2=可移动 3=固定；1=空读卡器、4=网络盘、5=光驱都不该在根上建暂存区
    let mut out = Vec::new();
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let letter = (b'A' + i as u8) as char;
        let wide: [u16; 4] = [letter as u16, b':' as u16, b'\\' as u16, 0];
        let kind = unsafe { GetDriveTypeW(wide.as_ptr()) };
        if kind == 2 || kind == 3 {
            out.push(letter);
        }
    }
    out
}

#[cfg(not(windows))]
fn local_drives() -> Vec<char> {
    Vec::new()
}

/// 扫一遍本地盘，列出真实存在的暂存区（每个盘一次 stat，不递归）。
pub fn discovered_staging_roots() -> Vec<PathBuf> {
    let letters: Vec<char> = if cfg!(windows) {
        let d = local_drives();
        if d.is_empty() {
            ('C'..='Z').collect()
        } else {
            d
        }
    } else {
        Vec::new()
    };
    let mut roots = Vec::new();
    for letter in letters {
        let cand = PathBuf::from(format!("{letter}:\\")).join(STAGING_DIR_NAME);
        if cand.is_dir() {
            roots.push(cand);
        }
    }
    roots
}

/// 盘点要覆盖的全部根：配置的工作目录 + 各盘暂存区（去重）。
pub fn all_scan_roots(workdir: &Path) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut candidates = vec![workdir.to_path_buf()];
    candidates.extend(discovered_staging_roots());
    for cand in candidates {
        let key = std::fs::canonicalize(&cand)
            .unwrap_or_else(|_| cand.clone())
            .to_string_lossy()
            .to_lowercase();
        if seen.insert(key) {
            roots.push(cand);
        }
    }
    roots
}

/// 符号链接 / junction / 其它重解析点——凡是「指向别处」的目录都算。
///
/// 必须查 reparse 标志位：Windows 上 junction 被 `is_symlink` 判为 false，
/// 但 rmtree 的后果同样是越界删除。查不出来时按 true 处理。
pub fn is_link_like(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return true;
    };
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

/// 工作目录下的直属 `task_<id>` 目录（只读一层，不递归；界面刷新会频繁调用）。
pub fn iter_task_dirs(root: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = rd
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .filter(|p| task_id_of(p).is_some())
        .collect();
    out.sort_by_key(|p| task_id_of(p).unwrap_or(i64::MAX));
    out
}

/// 配置的工作目录 + 各盘暂存区里的全部 `task_<id>` 目录。
pub fn iter_all_task_dirs(workdir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in all_scan_roots(workdir) {
        out.extend(iter_task_dirs(&root));
    }
    out.sort_by_key(|p| task_id_of(p).unwrap_or(i64::MAX));
    out
}

/// 递归统计 (字节数, 文件数)。跳过链接/junction，避免跟着它们数到别的卷上。
pub fn dir_size(path: &Path, count_limit: usize) -> (u64, usize) {
    let mut total = 0u64;
    let mut files = 0usize;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_dir() {
                if !is_link_like(&entry.path()) {
                    stack.push(entry.path());
                }
            } else {
                if let Ok(meta) = entry.metadata() {
                    total += meta.len();
                }
                files += 1;
                if files >= count_limit {
                    return (total, files);
                }
            }
        }
    }
    (total, files)
}

fn inside(path: &Path, root: &Path) -> bool {
    // canonicalize 要求路径存在；库里的记录可能指向已搬走的位置，所以失败时
    // 退回「相对 root 拼接 + 字符串前缀」比较（Windows 大小写不敏感）。
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let canon_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    if let Ok(canon) = std::fs::canonicalize(&abs) {
        if canon.starts_with(&canon_root) {
            return true;
        }
    }
    if let Ok(rel) = abs.strip_prefix(root) {
        if canon_root.join(rel).starts_with(&canon_root) {
            return true;
        }
    }
    let pl = abs.to_string_lossy().to_lowercase();
    let rl = canon_root.to_string_lossy().to_lowercase();
    let raw = root.to_string_lossy().to_lowercase();
    pl.starts_with(&rl) || pl.starts_with(&raw)
}

/// 给一个残留目录定性。顺序即优先级：越是「删了就找不回来」的判定越靠前。
pub fn classify(_path: &Path, task: Option<&StoredTask>, root: &Path) -> (LeftoverKind, String) {
    let Some(task) = task else {
        return (
            LeftoverKind::Orphan,
            "数据库里没有这条任务记录，无法判断产物是否已交付".into(),
        );
    };
    if task.status != TaskStatus::Done {
        return (
            LeftoverKind::Unfinished,
            format!("任务状态为「{}」，没有成功结束", task.status.as_str()),
        );
    }
    if !task.delivery_error.is_empty() {
        return (
            LeftoverKind::NotDelivered,
            format!("交付失败：{}", task.delivery_error),
        );
    }
    if !task.extracted_dir.is_empty() && inside(Path::new(&task.extracted_dir), root) {
        return (
            LeftoverKind::NotDelivered,
            "库中记录的产物位置仍指向工作目录，可能还没搬出去".into(),
        );
    }
    if !task.extracted_dir.is_empty() {
        return (
            LeftoverKind::Cleanable,
            format!(
                "产物已交付到 {}，这份是工作目录里的副本",
                task.extracted_dir
            ),
        );
    }
    (
        LeftoverKind::Orphan,
        "任务未记录产物位置，无法判断是否已交付".into(),
    )
}

/// 盘点残留。store 传 None 时所有目录都按孤儿处理。
pub fn scan(workdir: &Path, store: Option<&TaskStore>, count_limit: usize) -> Vec<Leftover> {
    let mut out = Vec::new();
    for root in all_scan_roots(workdir) {
        for d in iter_task_dirs(&root) {
            let task_id = task_id_of(&d);
            let task = task_id
                .and_then(|id| store.and_then(|s| s.get(id).ok().flatten()));
            let (kind, reason) = classify(&d, task.as_ref(), &root);
            let (size, files) = dir_size(&d, count_limit);
            out.push(Leftover {
                task_id,
                mtime: std::fs::metadata(&d).and_then(|m| m.modified()).ok(),
                path: d,
                kind,
                reason,
                size,
                files,
            });
        }
    }
    out
}

fn remove_dir_force(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(first) => {
            // 只读文件在 Windows 上会让 unlink 直接 WinError 5：清掉只读位再试
            clear_readonly(path);
            std::fs::remove_dir_all(path).map_err(|_| first)
        }
    }
}

fn clear_readonly(path: &Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        if perms.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    if let Ok(rd) = std::fs::read_dir(path) {
        for entry in rd.flatten() {
            clear_readonly(&entry.path());
        }
    }
}

/// 删除给定残留，返回 (释放的字节数, 失败原因列表)。默认只删 safe 的项。
pub fn prune(leftovers: &[Leftover], workdir: &Path, allow_unsafe: bool) -> (u64, Vec<String>) {
    let allowed: std::collections::HashSet<String> = all_scan_roots(workdir)
        .iter()
        .map(|r| {
            std::fs::canonicalize(r)
                .unwrap_or_else(|_| r.clone())
                .to_string_lossy()
                .to_lowercase()
        })
        .collect();

    let mut freed = 0u64;
    let mut errors = Vec::new();
    for lo in leftovers {
        let path = &lo.path;
        if !allow_unsafe && !lo.safe() {
            errors.push(format!("跳过（{}）：{}", lo.kind.label(), path.display()));
            continue;
        }
        if !path.is_dir() {
            errors.push(format!("跳过（已不存在）：{}", path.display()));
            continue;
        }
        if is_link_like(path) {
            errors.push(format!(
                "跳过（是链接/junction，删除会越界）：{}",
                path.display()
            ));
            continue;
        }
        let Ok(canon) = std::fs::canonicalize(path) else {
            errors.push(format!("跳过（路径无法解析）：{}", path.display()));
            continue;
        };
        let parent = canon
            .parent()
            .map(|p| p.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if !allowed.contains(&parent) {
            errors.push(format!(
                "跳过（不是已认领暂存根的直属子目录）：{}",
                path.display()
            ));
            continue;
        }
        if task_id_of(path).is_none() {
            errors.push(format!("跳过（目录名不是 task_<id>）：{}", path.display()));
            continue;
        }
        let size = if lo.size > 0 {
            lo.size
        } else {
            dir_size(path, usize::MAX).0
        };
        match remove_dir_force(path) {
            Ok(()) => freed += size,
            Err(e) => errors.push(format!("删除失败：{} — {e}", path.display())),
        }
    }
    (freed, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "jieya_cleanup_{tag}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64 % 1_000_000_000)
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn task_dir_names_are_parsed_strictly() {
        assert_eq!(task_id_of(Path::new(r"C:\w\task_12")), Some(12));
        assert_eq!(task_id_of(Path::new(r"C:\w\task_x")), None);
        assert_eq!(task_id_of(Path::new(r"C:\w\other")), None);
    }

    #[test]
    fn classify_prefers_keep_over_clean() {
        let root = temp_root("classify");
        let dir = root.join("task_1");
        std::fs::create_dir_all(&dir).unwrap();

        let mut task = StoredTask {
            id: 1,
            archive_path: "a.zip".into(),
            archive_fingerprint: String::new(),
            parent_id: None,
            depth: 0,
            source: String::new(),
            status: TaskStatus::Extracting,
            password_used: None,
            error: String::new(),
            extracted_dir: String::new(),
            delivery_error: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        };
        assert_eq!(classify(&dir, Some(&task), &root).0, LeftoverKind::Unfinished);

        task.status = TaskStatus::Done;
        task.delivery_error = "磁盘已满".into();
        assert_eq!(classify(&dir, Some(&task), &root).0, LeftoverKind::NotDelivered);

        task.delivery_error.clear();
        task.extracted_dir = root.join("task_1").join("out").to_string_lossy().into();
        assert_eq!(classify(&dir, Some(&task), &root).0, LeftoverKind::NotDelivered);

        task.extracted_dir = r"D:\downloads\a".into();
        assert_eq!(classify(&dir, Some(&task), &root).0, LeftoverKind::Cleanable);

        assert_eq!(classify(&dir, None, &root).0, LeftoverKind::Orphan);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn prune_removes_only_cleanable_by_default() {
        let root = temp_root("prune");
        let clean = root.join("task_1");
        let keep = root.join("task_2");
        std::fs::create_dir_all(clean.join("out")).unwrap();
        std::fs::write(clean.join("out").join("f.bin"), vec![0u8; 1024]).unwrap();
        std::fs::create_dir_all(keep.join("out")).unwrap();
        std::fs::write(keep.join("out").join("f.bin"), b"keep").unwrap();

        let leftovers = vec![
            Leftover {
                path: clean.clone(),
                task_id: Some(1),
                kind: LeftoverKind::Cleanable,
                reason: String::new(),
                size: 1024,
                files: 1,
                mtime: None,
            },
            Leftover {
                path: keep.clone(),
                task_id: Some(2),
                kind: LeftoverKind::NotDelivered,
                reason: String::new(),
                size: 4,
                files: 1,
                mtime: None,
            },
        ];
        let (freed, errors) = prune(&leftovers, &root, false);
        assert_eq!(freed, 1024);
        assert_eq!(errors.len(), 1);
        assert!(!clean.exists());
        assert!(keep.exists());

        let (freed2, errors2) = prune(&leftovers, &root, true);
        assert_eq!(freed2, 4, "{errors2:?}");
        assert!(!keep.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn prune_refuses_dirs_outside_claimed_roots() {
        let root = temp_root("outside");
        let other = temp_root("outside_other");
        let victim = other.join("task_9");
        std::fs::create_dir_all(&victim).unwrap();
        let leftovers = vec![Leftover {
            path: victim.clone(),
            task_id: Some(9),
            kind: LeftoverKind::Cleanable,
            reason: String::new(),
            size: 0,
            files: 0,
            mtime: None,
        }];
        let (freed, errors) = prune(&leftovers, &root, true);
        assert_eq!(freed, 0);
        assert!(errors[0].contains("不是已认领暂存根"), "{errors:?}");
        assert!(victim.exists());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&other);
    }
}
