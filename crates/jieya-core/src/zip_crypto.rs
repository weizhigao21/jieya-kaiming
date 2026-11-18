//! ZIP 加密支持：ZipCrypto 预筛 + WinZip-AES（method 99）进程内解密。
//!
//! **为什么要自己实现 AES**：7-Zip 的 zip-AES 密码路径对非 ASCII 是坏的
//! （中文密码的 AES 包永远报"密码错误"），而 WinRAR / Bandizip 造的中文密码
//! AES 包在国内网盘资源里是主流形态。这里按规范自己算：
//!
//! 1. 密钥材料 = PBKDF2-HMAC-SHA1(password_utf8, salt, 1000, 2*keylen + 2)
//! 2. 正文 AES-CTR：16 字节计数块，小端，从 1 开始
//! 3. 完整性 = HMAC-SHA1(mac_key, 密文)[:10]
//! 4. 真实压缩方式在 0x9901 附加字段里（0 = store，8 = deflate）
//!
//! 只在「每一条普通文件都是 AES、方法 store/deflate、无 zip64、无强加密」时才接手，
//! 其它一律交回 7z——只在自己能给出确定结果的地方替代它。

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use aes::{Aes128, Aes192, Aes256};
use cipher::{BlockEncrypt, KeyInit};
use crc32fast::Hasher;
use flate2::{Decompress, FlushDecompress};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

use crate::zip_dir;

const AUTH_SIZE: usize = 10;
const CHUNK: usize = 4 * 1024 * 1024;
const AES_EXTRA_TAG: u16 = 0x9901;

#[derive(Debug, thiserror::Error)]
pub enum AesError {
    #[error("密码校验值不匹配")]
    WrongPassword,
    #[error("不是可解密的 WinZip-AES 压缩包: {0}")]
    Structure(String),
    #[error("读取失败: {0}")]
    Io(#[from] std::io::Error),
    #[error("包已损坏: {0}")]
    Corrupt(String),
    #[error("已取消")]
    Cancelled,
}

// ---------------------------------------------------------------------------
// ZipCrypto 预筛
// ---------------------------------------------------------------------------

fn crc_table() -> &'static [u32; 256] {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [0u32; 256];
        for (i, slot) in table.iter_mut().enumerate() {
            let mut v = i as u32;
            for _ in 0..8 {
                v = if v & 1 != 0 { (v >> 1) ^ 0xEDB8_8320 } else { v >> 1 };
            }
            *slot = v;
        }
        table
    })
}

fn zipcrypto_last_byte(password: &[u8], header: &[u8]) -> u8 {
    let table = crc_table();
    let (mut k0, mut k1, mut k2) = (0x1234_5678u32, 0x2345_6789u32, 0x3456_7890u32);
    for &c in password {
        k0 = (k0 >> 8) ^ table[((k0 ^ c as u32) & 0xFF) as usize];
        k1 = (k1.wrapping_add(k0 & 0xFF))
            .wrapping_mul(13_477_5813)
            .wrapping_add(1);
        k2 = (k2 >> 8) ^ table[((k2 ^ (k1 >> 24)) & 0xFF) as usize];
    }
    let mut plain = 0u8;
    for &c in header {
        let temp = k2 | 2;
        plain = c ^ (((temp.wrapping_mul(temp ^ 1)) >> 8) & 0xFF) as u8;
        k0 = (k0 >> 8) ^ table[((k0 ^ plain as u32) & 0xFF) as usize];
        k1 = (k1.wrapping_add(k0 & 0xFF))
            .wrapping_mul(13_477_5813)
            .wrapping_add(1);
        k2 = (k2 >> 8) ^ table[((k2 ^ (k1 >> 24)) & 0xFF) as usize];
    }
    plain
}

#[derive(Debug, Clone)]
pub enum FilterKind {
    ZipCrypto,
    Aes { key_size: usize },
}

#[derive(Debug, Clone)]
pub struct ZipFilter {
    pub data: Vec<u8>,
    pub verifier: Vec<u8>,
    pub kind: FilterKind,
}

impl ZipFilter {
    /// False = 可排除；True = 需要真实解压，绝不是成功判据。
    pub fn may_match(&self, password: &str) -> bool {
        if !password.is_ascii() {
            return true;
        }
        match self.kind {
            FilterKind::ZipCrypto => {
                zipcrypto_last_byte(password.as_bytes(), &self.data) == self.verifier[0]
            }
            FilterKind::Aes { key_size } => {
                let derived = derive(password.as_bytes(), &self.data, key_size);
                derived.2.as_slice() == self.verifier.as_slice()
            }
        }
    }
}

fn read_at(f: &mut File, offset: u64, len: usize) -> Option<Vec<u8>> {
    f.seek(SeekFrom::Start(offset)).ok()?;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf).ok()?;
    Some(buf)
}

pub fn make_filter(path: &Path) -> Option<ZipFilter> {
    let entries = zip_dir::read_entries(path)?;
    let first = entries
        .iter()
        .find(|e| e.flags & 1 != 0 && !zip_dir::is_dir_name(&e.name_raw))?;
    if first.flags & (0x40 | 0x2000) != 0 {
        return None;
    }
    let local = zip_dir::read_local_header(path, first.local_offset)?;
    if local.flags != first.flags || local.method != first.method {
        return None;
    }
    let local_fields = zip_dir::extra_fields(&local.extra)?;
    let central_fields = zip_dir::extra_fields(&first.extra)?;
    if local_fields.contains_key(&0x0017) || central_fields.contains_key(&0x0017) {
        return None; // PKWARE Strong Encryption
    }
    let data_start =
        first.local_offset + 30 + local.name_raw.len() as u64 + local.extra.len() as u64;
    let mut f = File::open(path).ok()?;

    if first.method == 99 {
        let aes = local_fields.get(&AES_EXTRA_TAG)?;
        if central_fields.get(&AES_EXTRA_TAG).map(|v| v.as_slice()) != Some(aes.as_slice()) {
            return None;
        }
        if aes.len() < 7 || !(1..=2).contains(&zip_dir::u16_at(aes, 0)?) || &aes[2..4] != b"AE" {
            return None;
        }
        let key_size = match aes[4] {
            1 => 16,
            2 => 24,
            3 => 32,
            _ => return None,
        };
        let salt_size = key_size / 2;
        if first.csize < (salt_size + 2 + AUTH_SIZE) as u64 {
            return None;
        }
        let head = read_at(&mut f, data_start, salt_size + 2)?;
        return Some(ZipFilter {
            data: head[..salt_size].to_vec(),
            verifier: head[salt_size..].to_vec(),
            kind: FilterKind::Aes { key_size },
        });
    }

    if local_fields.contains_key(&AES_EXTRA_TAG) || central_fields.contains_key(&AES_EXTRA_TAG) {
        return None;
    }
    if first.csize < 12 {
        return None;
    }
    let check = if first.flags & 8 != 0 {
        // 流式写入（bit 3）：头部 CRC 为空，校验字节取 DOS 时间高字节
        (local.dos_time >> 8) as u8
    } else {
        if local.crc != first.crc {
            return None;
        }
        (local.crc >> 24) as u8
    };
    let data = read_at(&mut f, data_start, 12)?;
    Some(ZipFilter {
        data,
        verifier: vec![check],
        kind: FilterKind::ZipCrypto,
    })
}

// ---------------------------------------------------------------------------
// WinZip-AES
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AesEntry {
    pub name: String,
    pub data_offset: u64,
    pub cipher_size: u64,
    pub file_size: u64,
    pub method: u16,
    pub key_size: usize,
    pub salt: Vec<u8>,
    pub verifier: Vec<u8>,
    pub auth_code: Vec<u8>,
    pub crc: u32,
}

fn derive(password: &[u8], salt: &[u8], key_size: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut material = vec![0u8; 2 * key_size + 2];
    pbkdf2_hmac::<Sha1>(password, salt, 1000, &mut material);
    (
        material[..key_size].to_vec(),
        material[key_size..2 * key_size].to_vec(),
        material[2 * key_size..].to_vec(),
    )
}

/// 纯 AES 的 ZIP 返回条目表；其它情况返回 None（交回 7z）。
pub fn scan(path: &Path) -> Option<Vec<AesEntry>> {
    let entries = zip_dir::read_entries(path)?;
    let mut f = File::open(path).ok()?;
    let mut out = Vec::new();
    for e in entries.iter().filter(|e| !zip_dir::is_dir_name(&e.name_raw)) {
        if e.method != 99 || e.flags & 0x40 != 0 {
            return None;
        }
        let local = zip_dir::read_local_header_at(&mut f, e.local_offset)?;
        let fields = zip_dir::extra_fields(&local.extra)?;
        let aes = fields.get(&AES_EXTRA_TAG)?;
        if aes.len() < 7 {
            return None;
        }
        let version = zip_dir::u16_at(aes, 0)?;
        let strength = aes[4];
        let real_method = zip_dir::u16_at(aes, 5)?;
        if !(1..=2).contains(&version) || &aes[2..4] != b"AE" {
            return None;
        }
        let key_size = match strength {
            1 => 16,
            2 => 24,
            3 => 32,
            _ => return None,
        };
        if !matches!(real_method, 0 | 8) {
            return None;
        }
        let salt_size = key_size / 2;
        if e.csize < (salt_size + 2 + AUTH_SIZE) as u64 {
            return None;
        }
        let cipher_size = e.csize - (salt_size + 2 + AUTH_SIZE) as u64;
        let data_start = e.local_offset + 30 + local.name_raw.len() as u64 + local.extra.len() as u64;
        let salt = read_at(&mut f, data_start, salt_size + 2)?;
        let auth = read_at(&mut f, data_start + salt_size as u64 + 2 + cipher_size, AUTH_SIZE)?;
        out.push(AesEntry {
            name: decode_name(&e.name_raw, e.flags),
            data_offset: data_start + salt_size as u64 + 2,
            cipher_size,
            file_size: e.usize,
            method: real_method,
            key_size,
            salt: salt[..salt_size].to_vec(),
            verifier: salt[salt_size..].to_vec(),
            auth_code: auth,
            crc: e.crc,
        });
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// 只看第一条的 2 字节校验值，不读正文。
pub fn verify(entries: &[AesEntry], password: &str) -> bool {
    let Some(first) = entries.first() else {
        return false;
    };
    let (_, _, check) = derive(password.as_bytes(), &first.salt, first.key_size);
    check == first.verifier
}

fn decode_name(raw: &[u8], flags: u16) -> String {
    // 置了 UTF-8 标志的直接按 UTF-8
    if flags & 0x800 != 0 {
        if let Ok(s) = std::str::from_utf8(raw) {
            return s.to_string();
        }
    }
    // 没置标志时先试 UTF-8（WinRAR/7z 常有"名字是 UTF-8 但标志没置"的包），
    // 再退 GBK；都解不动才按字节原样当字符，宁可丑也不丢字
    if let Ok(s) = std::str::from_utf8(raw) {
        return s.to_string();
    }
    let (cow, _, had_errors) = encoding_rs::GBK.decode(raw);
    if !had_errors {
        cow.into_owned()
    } else {
        raw.iter().map(|b| *b as char).collect()
    }
}

enum BlockCipher {
    A128(Aes128),
    A192(Aes192),
    A256(Aes256),
}

impl BlockCipher {
    fn new(key: &[u8]) -> Option<Self> {
        match key.len() {
            16 => Some(BlockCipher::A128(Aes128::new_from_slice(key).ok()?)),
            24 => Some(BlockCipher::A192(Aes192::new_from_slice(key).ok()?)),
            32 => Some(BlockCipher::A256(Aes256::new_from_slice(key).ok()?)),
            _ => None,
        }
    }

    fn encrypt_block(&self, block: &mut [u8; 16]) {
        match self {
            BlockCipher::A128(c) => c.encrypt_block(cipher::Block::<Aes128>::from_mut_slice(block)),
            BlockCipher::A192(c) => c.encrypt_block(cipher::Block::<Aes192>::from_mut_slice(block)),
            BlockCipher::A256(c) => c.encrypt_block(cipher::Block::<Aes256>::from_mut_slice(block)),
        }
    }
}

/// WinZip-AES 的计数器：小端 128 位，从 1 开始
struct Ctr {
    cipher: BlockCipher,
    next: u128,
}

impl Ctr {
    fn new(key: &[u8]) -> Option<Self> {
        Some(Self {
            cipher: BlockCipher::new(key)?,
            next: 1,
        })
    }

    fn xor(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            block.copy_from_slice(&self.next.to_le_bytes());
            self.next = self.next.wrapping_add(1);
            self.cipher.encrypt_block(&mut block);
            for (i, b) in chunk.iter().enumerate() {
                out.push(*b ^ block[i]);
            }
        }
        out
    }
}

/// 把条目名落成 dest 下的路径；越界（绝对路径、盘符、`..`）一律拒收
fn safe_target(dest: &Path, name: &str) -> Option<PathBuf> {
    let cleaned = name.replace('\\', "/");
    let cleaned = cleaned.trim_start_matches('/');
    let parts: Vec<&str> = cleaned
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    if parts.is_empty() || parts.iter().any(|p| *p == "..") || parts[0].contains(':') {
        return None;
    }
    Some(parts.iter().fold(dest.to_path_buf(), |acc, p| acc.join(p)))
}

/// 解密并解压到 dest，返回写出的文件数。密码不对返回 `WrongPassword`。
pub fn extract(
    archive: &Path,
    dest: &Path,
    password: &str,
    entries: &[AesEntry],
    on_progress: Option<&dyn Fn(u8)>,
    should_cancel: Option<&dyn Fn() -> bool>,
) -> Result<usize, AesError> {
    if entries.is_empty() {
        return Err(AesError::Structure("没有可解密的条目".into()));
    }
    let total: u64 = entries.iter().map(|e| e.file_size).max().unwrap_or(1).max(1);
    std::fs::create_dir_all(dest)?;

    let mut source = File::open(archive)?;
    let mut written = 0usize;

    for entry in entries {
        if let Some(cancel) = should_cancel {
            if cancel() {
                return Err(AesError::Cancelled);
            }
        }
        let (enc_key, mac_key, check) = derive(password.as_bytes(), &entry.salt, entry.key_size);
        if check != entry.verifier {
            return Err(AesError::WrongPassword);
        }
        let Some(target) = safe_target(dest, &entry.name) else {
            continue; // 越界条目跳过，不落盘
        };
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&mac_key)
            .map_err(|e| AesError::Structure(e.to_string()))?;
        let mut ctr =
            Ctr::new(&enc_key).ok_or_else(|| AesError::Structure("AES 密钥长度不支持".into()))?;
        let mut crc = Hasher::new();
        let mut out = std::io::BufWriter::new(File::create(&target)?);

        let mut inflater = if entry.method == 8 {
            Some(Decompress::new(false))
        } else {
            None
        };
        let mut outbuf = vec![0u8; 1024 * 1024];
        let mut done = 0u64;

        source.seek(SeekFrom::Start(entry.data_offset))?;
        let mut remaining = entry.cipher_size;
        while remaining > 0 {
            if let Some(cancel) = should_cancel {
                if cancel() {
                    return Err(AesError::Cancelled);
                }
            }
            let take = CHUNK.min(remaining as usize);
            let mut buf = vec![0u8; take];
            source.read_exact(&mut buf)?;
            remaining -= take as u64;
            mac.update(&buf);
            let plain = ctr.xor(&buf);

            match inflater.as_mut() {
                None => {
                    crc.update(&plain);
                    out.write_all(&plain)?;
                    done += plain.len() as u64;
                }
                Some(d) => {
                    let mut consumed = 0usize;
                    while consumed < plain.len() {
                        let before_in = d.total_in();
                        let before_out = d.total_out();
                        d.decompress(&plain[consumed..], &mut outbuf, FlushDecompress::None)
                            .map_err(|e| AesError::Corrupt(e.to_string()))?;
                        let used = (d.total_in() - before_in) as usize;
                        let produced = (d.total_out() - before_out) as usize;
                        if produced > 0 {
                            crc.update(&outbuf[..produced]);
                            out.write_all(&outbuf[..produced])?;
                            done += produced as u64;
                        }
                        if used == 0 && produced == 0 {
                            break;
                        }
                        consumed += used;
                    }
                }
            }
            if let Some(cb) = on_progress {
                cb((done * 100 / total).min(99) as u8);
            }
        }

        // deflate 收尾
        if let Some(d) = inflater.as_mut() {
            loop {
                let before_out = d.total_out();
                let status = d
                    .decompress(&[], &mut outbuf, FlushDecompress::Finish)
                    .map_err(|e| AesError::Corrupt(e.to_string()))?;
                let produced = (d.total_out() - before_out) as usize;
                if produced > 0 {
                    crc.update(&outbuf[..produced]);
                    out.write_all(&outbuf[..produced])?;
                }
                if produced == 0 || status == flate2::Status::StreamEnd {
                    break;
                }
            }
        }

        out.flush()?;
        drop(out);

        let digest = mac.finalize().into_bytes();
        if digest[..AUTH_SIZE] != entry.auth_code[..] {
            return Err(AesError::WrongPassword);
        }
        let actual_crc = crc.finalize();
        if entry.crc != 0 && actual_crc != entry.crc {
            return Err(AesError::Corrupt(format!(
                "{}: CRC 校验失败，包可能已损坏",
                entry.name
            )));
        }
        written += 1;
    }

    if let Some(cb) = on_progress {
        cb(100);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zipcrypto_prefilter_rejects_wrong_password() {
        let header = [0u8; 12];
        let a = zipcrypto_last_byte(b"right-password", &header);
        let b = zipcrypto_last_byte(b"wrong-password", &header);
        assert_ne!(a, b);
    }

    #[test]
    fn crc_table_matches_known_value() {
        let t = crc_table();
        assert_eq!(t[0], 0);
        assert_eq!(t[1], 0x7707_3096);
    }
}
