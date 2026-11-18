//! 定位视频/SFX 文件里的内嵌 ZIP，去掉前缀和干扰尾部后交给正常解压流程。
//!
//! 素材站常见的「.mp4 其实是 ZIP + 视频壳」：ZIP 数据前面有一段视频头，
//! 后面被拼了 RAR 之类的假数据。直接扔给 7z 会认错，所以这里用**尾部的
//! 中央目录**反推真实边界，只复制 [start, end) 那一段出来解。
//!
//! 只读尾部 1 MB 做验证，普通大视频不会被全文件扫描。

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const TAIL_SIZE: u64 = 1024 * 1024;
const EOCD: [u8; 4] = [b'P', b'K', 0x05, 0x06];
const LOCAL: [u8; 4] = [b'P', b'K', 0x03, 0x04];

#[derive(Debug, Clone)]
pub struct EmbeddedZip {
    pub start: u64,
    pub end: u64,
    pub members: Vec<String>,
}

/// 这些格式本身就是正常压缩包，内部即便含 ZIP 也不能当视频外壳剥离。
fn is_normal_archive(head: &[u8]) -> bool {
    head.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) // 7z
        || head.starts_with(b"Rar!\x1a\x07")
        || head.starts_with(&[0x1F, 0x8B]) // gzip
        || head.starts_with(b"BZh")
        || head.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) // xz
        || head.starts_with(b"MSCF") // cab
        || head.starts_with(b"MSWIM") // wim
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// 从尾部 EOCD 反推 ZIP 的真实起止；普通文件返回 None。
pub fn find_embedded_zip(path: &Path) -> Option<EmbeddedZip> {
    let size = std::fs::metadata(path).ok()?.len();
    if size < 22 {
        return None;
    }
    let mut f = File::open(path).ok()?;
    let mut head = [0u8; 8];
    f.read_exact(&mut head).ok()?;
    if is_normal_archive(&head) {
        return None;
    }

    let tail_start = size.saturating_sub(TAIL_SIZE);
    f.seek(SeekFrom::Start(tail_start)).ok()?;
    let mut tail = Vec::new();
    f.read_to_end(&mut tail).ok()?;

    let mut search_end = tail.len();
    for _ in 0..64 {
        let pos = rfind(&tail[..search_end], &EOCD)?;
        search_end = pos;
        if pos + 22 > tail.len() {
            continue;
        }
        let disk = u16_at(&tail, pos + 4)?;
        let cd_disk = u16_at(&tail, pos + 6)?;
        let count_disk = u16_at(&tail, pos + 8)?;
        let count = u16_at(&tail, pos + 10)?;
        let cd_size = u32_at(&tail, pos + 12)? as u64;
        let cd_offset = u32_at(&tail, pos + 16)? as u64;
        let comment = u16_at(&tail, pos + 20)? as u64;
        let end = tail_start + pos as u64 + 22 + comment;
        if disk != 0 || cd_disk != 0 || count_disk != count || end > size || cd_size > tail_start + pos as u64 {
            continue;
        }
        let eocd_abs = tail_start + pos as u64;
        let Some(cd_abs) = eocd_abs.checked_sub(cd_size) else {
            continue;
        };
        let Some(start) = cd_abs.checked_sub(cd_offset) else {
            continue;
        };
        if start >= end {
            continue;
        }

        // 起点必须是本地头或空包 EOCD
        let mut probe = [0u8; 4];
        f.seek(SeekFrom::Start(start)).ok()?;
        f.read_exact(&mut probe).ok()?;
        if probe != LOCAL && probe != EOCD {
            continue;
        }

        // 校验中央目录能顺序读完，顺带收条目名
        let Some(members) = read_member_names(&mut f, cd_abs, count as usize, cd_size) else {
            continue;
        };
        if start > 0 || end < size {
            return Some(EmbeddedZip { start, end, members });
        }
        return None; // 普通 ZIP 不需要复制
    }
    None
}

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .rev()
        .find(|&i| &haystack[i..i + needle.len()] == needle)
}

fn read_member_names(f: &mut File, cd_abs: u64, count: usize, cd_size: u64) -> Option<Vec<String>> {
    f.seek(SeekFrom::Start(cd_abs)).ok()?;
    let mut buf = vec![0u8; cd_size as usize];
    f.read_exact(&mut buf).ok()?;
    let mut pos = 0usize;
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        if u32_at(&buf, pos)? != 0x0201_4B50 {
            return None;
        }
        let flags = u16_at(&buf, pos + 8)?;
        let nlen = u16_at(&buf, pos + 28)? as usize;
        let xlen = u16_at(&buf, pos + 30)? as usize;
        let clen = u16_at(&buf, pos + 32)? as usize;
        let raw = buf.get(pos + 46..pos + 46 + nlen)?;
        names.push(decode_name(raw, flags));
        pos += 46 + nlen + xlen + clen;
    }
    Some(names)
}

fn decode_name(raw: &[u8], flags: u16) -> String {
    if flags & 0x800 != 0 {
        if let Ok(s) = std::str::from_utf8(raw) {
            return s.to_string();
        }
    }
    if let Ok(s) = std::str::from_utf8(raw) {
        return s.to_string();
    }
    let (cow, _, had) = encoding_rs::GBK.decode(raw);
    if !had {
        cow.into_owned()
    } else {
        raw.iter().map(|b| *b as char).collect()
    }
}

/// 恢复出来的临时 ZIP：Drop 时删掉整个临时目录。
pub struct Recovered {
    dir: PathBuf,
    path: PathBuf,
}

impl Recovered {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Recovered {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 有内嵌 ZIP 就复制到 workdir 下的临时目录并返回；普通文件返回 Ok(None)。
pub fn prepare(
    path: &Path,
    workdir: &Path,
    should_cancel: Option<&dyn Fn() -> bool>,
    on_progress: Option<&dyn Fn(u8)>,
) -> crate::Result<Option<Recovered>> {
    let Some(bounds) = find_embedded_zip(path) else {
        return Ok(None);
    };
    std::fs::create_dir_all(workdir)?;
    // 用进程号 + 纳秒做唯一名，不引 rand
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = workdir.join(format!("embedded_zip_{}_{}", std::process::id(), nonce));
    std::fs::create_dir_all(&dir)?;
    let recovered = dir.join("payload.zip");

    let total = bounds.end - bounds.start;
    let mut copied = 0u64;
    if let Some(cb) = on_progress {
        cb(0);
    }
    let mut source = File::open(path)?;
    let mut output = std::io::BufWriter::new(File::create(&recovered)?);
    source.seek(SeekFrom::Start(bounds.start))?;
    while copied < total {
        if let Some(cancel) = should_cancel {
            if cancel() {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(crate::Error::Cancelled);
            }
        }
        let want = (8 * 1024 * 1024).min(total - copied) as usize;
        let mut block = vec![0u8; want];
        source.read_exact(&mut block).map_err(|_| {
            crate::Error::Other("读取内嵌 ZIP 时文件提前结束，源文件可能正在被修改".into())
        })?;
        output.write_all(&block)?;
        copied += want as u64;
        if let Some(cb) = on_progress {
            cb((copied * 100 / total) as u8);
        }
    }
    output.flush()?;
    Ok(Some(Recovered { dir, path: recovered }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "jieya_embedded_{tag}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64 % 1_000_000_000)
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 手写一个最小 ZIP（store 方式），返回字节
    fn zip_bytes(name: &[u8], payload: &[u8]) -> Vec<u8> {
        let crc = crc32fast::hash(payload);
        let mut local = Vec::new();
        local.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        local.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name);
        local.extend_from_slice(payload);

        let mut cd = Vec::new();
        cd.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(name);

        let mut out = local;
        let cd_off = out.len() as u32;
        out.extend_from_slice(&cd);
        out.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // disk
        out.extend_from_slice(&0u16.to_le_bytes()); // cd_disk
        out.extend_from_slice(&1u16.to_le_bytes()); // count_disk
        out.extend_from_slice(&1u16.to_le_bytes()); // count
        out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn plain_zip_is_not_embedded() {
        let dir = temp_dir("plain");
        let p = dir.join("plain.zip");
        std::fs::write(&p, zip_bytes(b"a.txt", b"hi")).unwrap();
        assert!(find_embedded_zip(&p).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prefixed_zip_with_junk_tail_is_found_and_recovered() {
        let dir = temp_dir("prefixed");
        let p = dir.join("video.mp4");
        let body = zip_bytes(b"secret.txt", b"payload");
        let mut data = vec![0u8; 4096]; // 假的视频头
        data[..4].copy_from_slice(b"\x00\x00\x00\x18");
        let start = data.len() as u64;
        data.extend_from_slice(&body);
        let end = data.len() as u64;
        data.extend_from_slice(b"Rar!\x1a\x07\x00fake tail"); // 干扰尾部
        std::fs::write(&p, &data).unwrap();

        let found = find_embedded_zip(&p).expect("应当识别出内嵌 ZIP");
        assert_eq!(found.start, start);
        assert_eq!(found.end, end);
        assert_eq!(found.members, vec!["secret.txt".to_string()]);

        let work = dir.join("work");
        let rec = prepare(&p, &work, None, None).unwrap().expect("应当恢复");
        let copied = std::fs::read(rec.path()).unwrap();
        assert_eq!(copied, body);
        drop(rec);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn real_archive_magic_is_skipped() {
        let dir = temp_dir("7z");
        let p = dir.join("a.7z");
        std::fs::write(&p, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 0]).unwrap();
        assert!(find_embedded_zip(&p).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
