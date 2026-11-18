//! ZIP 中央目录的最小解析：只取我们要的字段，原始名字字节一个不丢。
//!
//! 单独抽出来的原因：密码系统（zip_crypto）和乱码修复（name_repair）都要读
//! 中央目录，而**原始文件名字节**正是乱码修复的关键证据——磁盘上的名字是
//! 「按某种代码页解出来的结果」，只有原始字节能无损还原。

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub flags: u16,
    pub method: u16,
    pub crc: u32,
    pub csize: u64,
    pub usize: u64,
    pub name_raw: Vec<u8>,
    pub extra: Vec<u8>,
    pub local_offset: u64,
}

pub struct LocalHeader {
    pub flags: u16,
    pub method: u16,
    pub crc: u32,
    pub dos_time: u16,
    pub name_raw: Vec<u8>,
    pub extra: Vec<u8>,
}

const EOCD_SIG: u32 = 0x0605_4b50;
const CD_SIG: u32 = 0x0201_4b50;
const LOCAL_SIG: u32 = 0x0403_4b50;

pub fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

pub fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn find_eocd(f: &mut File) -> Option<(u64, u64, u16)> {
    let size = f.metadata().ok()?.len();
    let tail_len = size.min(65557) as usize;
    f.seek(SeekFrom::Start(size - tail_len as u64)).ok()?;
    let mut tail = vec![0u8; tail_len];
    f.read_exact(&mut tail).ok()?;
    let mut idx = None;
    let mut i = tail_len.saturating_sub(22);
    loop {
        if tail[i..i + 4] == EOCD_SIG.to_le_bytes() {
            idx = Some(i);
            break;
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    let i = idx?;
    let disk = u16_at(&tail, i + 4)?;
    let cd_disk = u16_at(&tail, i + 6)?;
    if disk != 0 || cd_disk != 0 {
        return None; // 分卷
    }
    let count = u16_at(&tail, i + 10)?;
    let cd_size = u32_at(&tail, i + 12)?;
    let cd_offset = u32_at(&tail, i + 16)?;
    if count == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF {
        return None; // zip64
    }
    Some((cd_offset as u64, cd_size as u64, count))
}

/// 读中央目录；不是 zip / 分卷 / zip64 / 结构异常一律 None。
pub fn read_entries(path: &Path) -> Option<Vec<DirEntry>> {
    let mut f = File::open(path).ok()?;
    let (cd_offset, cd_size, count) = find_eocd(&mut f)?;
    f.seek(SeekFrom::Start(cd_offset)).ok()?;
    let mut buf = vec![0u8; cd_size as usize];
    f.read_exact(&mut buf).ok()?;

    let mut out = Vec::with_capacity(count as usize);
    let mut pos = 0usize;
    for _ in 0..count {
        if u32_at(&buf, pos)? != CD_SIG {
            return None;
        }
        let flags = u16_at(&buf, pos + 8)?;
        let method = u16_at(&buf, pos + 10)?;
        let crc = u32_at(&buf, pos + 16)?;
        let csize = u32_at(&buf, pos + 20)? as u64;
        let usize = u32_at(&buf, pos + 24)? as u64;
        let nlen = u16_at(&buf, pos + 28)? as usize;
        let xlen = u16_at(&buf, pos + 30)? as usize;
        let clen = u16_at(&buf, pos + 32)? as usize;
        let local_offset = u32_at(&buf, pos + 42)? as u64;
        if csize == 0xFFFF_FFFF || usize == 0xFFFF_FFFF || local_offset == 0xFFFF_FFFF {
            return None;
        }
        let name_start = pos + 46;
        let name_raw = buf.get(name_start..name_start + nlen)?.to_vec();
        let extra = buf.get(name_start + nlen..name_start + nlen + xlen)?.to_vec();
        out.push(DirEntry {
            flags,
            method,
            crc,
            csize,
            usize,
            name_raw,
            extra,
            local_offset,
        });
        pos = name_start + nlen + xlen + clen;
    }
    Some(out)
}

/// 读一个条目的本地头（含原始名字与附加字段）。
pub fn read_local_header(path: &Path, offset: u64) -> Option<LocalHeader> {
    let mut f = File::open(path).ok()?;
    read_local_header_at(&mut f, offset)
}

/// 复用已打开的句柄版本：多条目循环里不要一条开一次文件。
pub fn read_local_header_at(f: &mut File, offset: u64) -> Option<LocalHeader> {
    f.seek(SeekFrom::Start(offset)).ok()?;
    let mut head = [0u8; 30];
    f.read_exact(&mut head).ok()?;
    if u32_at(&head, 0)? != LOCAL_SIG {
        return None;
    }
    let flags = u16_at(&head, 6)?;
    let method = u16_at(&head, 8)?;
    let dos_time = u16_at(&head, 10)?;
    let crc = u32_at(&head, 14)?;
    let nlen = u16_at(&head, 26)? as usize;
    let xlen = u16_at(&head, 28)? as usize;
    let mut name_raw = vec![0u8; nlen];
    let mut extra = vec![0u8; xlen];
    f.read_exact(&mut name_raw).ok()?;
    f.read_exact(&mut extra).ok()?;
    Some(LocalHeader {
        flags,
        method,
        crc,
        dos_time,
        name_raw,
        extra,
    })
}

/// 附加字段解析（重复 tag 视为结构异常）
pub fn extra_fields(extra: &[u8]) -> Option<HashMap<u16, Vec<u8>>> {
    let mut fields = HashMap::new();
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let tag = u16_at(extra, pos)?;
        let size = u16_at(extra, pos + 2)? as usize;
        pos += 4;
        if pos + size > extra.len() || fields.contains_key(&tag) {
            return None;
        }
        fields.insert(tag, extra[pos..pos + size].to_vec());
        pos += size;
    }
    if pos != extra.len() {
        return None;
    }
    Some(fields)
}

pub fn is_dir_name(name: &[u8]) -> bool {
    name.ends_with(b"/") || name.ends_with(b"\\")
}
