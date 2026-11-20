//! 7z 密码快筛：纯 Rust 直接读一个加密条目，不启动 7z 进程。
//!
//! 只负责“密码对不对”，正式解压仍交给 7z。这样既省掉命令行进程和
//! 19GB 包头的反复扫描，又不用自己实现 BCJ2/PPMd/分卷这些边缘格式。

use std::path::Path;

use sevenz_rust2::{ArchiveReader, Error};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    Match,
    Wrong,
    Unsupported(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Batch {
    Found(String),
    AllWrong(usize),
    Unsupported(String),
    Failed(String),
}

fn is_bad_password(err: &Error) -> bool {
    matches!(
        err,
        Error::MaybeBadPassword(_) | Error::PasswordRequired
    )
}

/// 选第一个可读的加密条目；没有逐条加密标记时退回第一个文件（头部加密包）。
fn test_entry(reader: &ArchiveReader<std::fs::File>) -> Option<String> {
    let archive = reader.archive();
    let encrypted = archive
        .files
        .iter()
        .enumerate()
        .find(|(i, f)| f.has_stream() && f.size() > 0 && archive.is_file_encrypted(*i))
        .map(|(i, _)| i);
    let first = archive
        .files
        .iter()
        .enumerate()
        .find(|(_, f)| f.has_stream() && f.size() > 0)
        .map(|(i, _)| i);
    encrypted
        .or(first)
        .map(|i| archive.files[i].name().to_string())
}

/// 返回 `Match` / `Wrong`；结构不支持时返回 `Unsupported`，调用方回退 7z。
pub fn verify(archive: &Path, password: &str) -> Probe {
    let mut reader = match ArchiveReader::open(archive, password.into()) {
        Ok(r) => r,
        Err(e) if is_bad_password(&e) => return Probe::Wrong,
        Err(e) => return Probe::Unsupported(format!("{e:?}")),
    };

    let Some(name) = test_entry(&reader) else {
        return Probe::Unsupported("没有可读条目".into());
    };

    match reader.read_file(&name) {
        Ok(_) => Probe::Match,
        Err(e) if is_bad_password(&e) => Probe::Wrong,
        Err(e) => Probe::Unsupported(format!("{e:?}")),
    }
}

/// 多线程快筛。命中就返回；全部错误返回 `AllWrong`；
/// 任一候选遇到不支持的结构就返回 `Unsupported`，让上层回退 7z。
pub fn probe_candidates(archive: &Path, candidates: &[String], threads: usize) -> Batch {
    let mut found = None;
    let mut tried = 0usize;
    let mut unsupported = None;

    std::thread::scope(|scope| {
        for chunk in candidates.chunks(threads.max(1)) {
            let handles: Vec<_> = chunk
                .iter()
                .map(|pwd| {
                    let archive = archive.to_path_buf();
                    let pwd = pwd.clone();
                    scope.spawn(move || {
                        let result = verify(&archive, &pwd);
                        (pwd, result)
                    })
                })
                .collect();

            for handle in handles {
                match handle.join() {
                    Ok((pwd, Probe::Match)) => found = Some(pwd),
                    Ok((_, Probe::Wrong)) => tried += 1,
                    Ok((_, Probe::Unsupported(msg))) => unsupported = Some(msg),
                    Err(_) => unsupported = Some("快筛线程异常".into()),
                }
            }
            if found.is_some() {
                break;
            }
        }
    });

    if let Some(pwd) = found {
        Batch::Found(pwd)
    } else if let Some(msg) = unsupported {
        Batch::Unsupported(msg)
    } else if tried > 0 {
        Batch::AllWrong(tried)
    } else {
        Batch::Failed("没有可试的候选密码".into())
    }
}
