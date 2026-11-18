use std::fs;
use std::path::{Path, PathBuf};

/// 递归列文件；符号链接/联接点不跟随（避免环）。
pub fn iter_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if file_type.is_dir() {
                if !is_link_like(&path) {
                    stack.push(path);
                }
            } else if file_type.is_file() {
                out.push(path);
            }
        }
    }
    out
}

/// Windows 上的目录联接（junction）在 file_type 里仍算目录，用属性位排除。
pub fn is_link_like(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if let Ok(meta) = fs::symlink_metadata(path) {
            return meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        }
        false
    }
    #[cfg(not(windows))]
    {
        fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
    }
}
