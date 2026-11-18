//! 加密容器（与 Python 版 `core/secure_bundle.py` 完全同格式）。
//!
//! 布局（全部定长大端）:
//!
//! ```text
//! magic  4B  b"JYKB"
//! ver    1B  1
//! kdf    1B  1 = scrypt
//! n_log2 1B
//! r      1B
//! p      1B
//! salt  16B
//! nonce 16B
//! mac   32B  HMAC-SHA256(mac_key, header + ciphertext)
//! ct     ..  AES-256-CTR（128 位大端计数器，初值 = nonce）
//! ```
//!
//! 存在的意义：密码库是私有数据，不能进公开仓库；加密后可以随便放网盘、
//! U 盘、私有仓库，泄露了也只是密文。

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use hmac::{Hmac, Mac};
use scrypt::{scrypt, Params};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 4] = b"JYKB";
const FORMAT_VERSION: u8 = 1;
const KDF_SCRYPT: u8 = 1;
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 16;
const MAC_SIZE: usize = 32;
const HEADER_SIZE: usize = 4 + 5 + SALT_SIZE + NONCE_SIZE; // 41
const DATA_OFFSET: usize = HEADER_SIZE + MAC_SIZE; // 73

pub const DEFAULT_N_LOG2: u8 = 15;
pub const DEFAULT_R: u8 = 8;
pub const DEFAULT_P: u8 = 1;

const MIN_N_LOG2: u8 = 10;
const MAX_N_LOG2: u8 = 17;
const MAX_R: u8 = 32;
const MAX_P: u8 = 16;

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("不是密码库备份文件（起始标记不匹配）")]
    NotBundle,
    #[error("文件太短，不是完整的密码库备份")]
    TooShort,
    #[error("备份文件的格式版本是 {0}，当前程序只认 {FORMAT_VERSION}")]
    BadVersion(u8),
    #[error("未知的密钥派生方式 {0}")]
    BadKdf(u8),
    #[error("KDF 强度参数 n_log2={0} 超出允许范围 {MIN_N_LOG2}~{MAX_N_LOG2}")]
    BadN(u8),
    #[error("KDF 参数 r={0}, p={1} 超出允许范围")]
    BadRP(u8, u8),
    #[error("口令不正确，或备份文件已损坏/被改动")]
    Auth,
    #[error("口令不能为空")]
    EmptyPassword,
    #[error("密钥派生失败: {0}")]
    Kdf(String),
}

pub struct BundleInfo {
    pub version: u8,
    pub n_log2: u8,
    pub r: u8,
    pub p: u8,
    pub ciphertext_size: usize,
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    // getrandom 在 Windows 上走 RtlGenRandom，失败基本不可能；真失败就退回时间熵
    if getrandom::getrandom(&mut buf).is_err() {
        use sha2::{Digest, Sha256};
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut seed: Vec<u8> = Vec::new();
        seed.extend_from_slice(nanos.to_le_bytes().as_slice());
        seed.extend_from_slice(&(std::process::id() as u64).to_le_bytes());
        let digest = Sha256::digest(&seed);
        for i in 0..N {
            buf[i] = digest[i % digest.len()];
        }
    }
    buf
}

fn derive(password: &str, salt: &[u8], n_log2: u8, r: u8, p: u8) -> Result<([u8; 32], [u8; 32]), BundleError> {
    let params = Params::new(n_log2, r as u32, p as u32, 64)
        .map_err(|e| BundleError::Kdf(e.to_string()))?;
    let mut out = [0u8; 64];
    scrypt(password.as_bytes(), salt, &params, &mut out)
        .map_err(|e| BundleError::Kdf(e.to_string()))?;
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&out[..32]);
    mac.copy_from_slice(&out[32..]);
    Ok((enc, mac))
}

/// 128 位大端计数器（与 ZIP 那套小端不同，别混用）
fn ctr_xor(key: &[u8; 32], nonce: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(key).expect("AES-256 接受 32 字节密钥");
    let mut counter = u128::from_be_bytes(*nonce);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = counter.to_be_bytes();
        cipher.encrypt_block(cipher::Block::<Aes256>::from_mut_slice(&mut block));
        for (i, byte) in chunk.iter().enumerate() {
            out.push(byte ^ block[i]);
        }
        counter = counter.wrapping_add(1);
    }
    out
}

fn check_params(n_log2: u8, r: u8, p: u8) -> Result<(), BundleError> {
    if !(MIN_N_LOG2..=MAX_N_LOG2).contains(&n_log2) {
        return Err(BundleError::BadN(n_log2));
    }
    if r == 0 || r > MAX_R || p == 0 || p > MAX_P {
        return Err(BundleError::BadRP(r, p));
    }
    Ok(())
}

pub fn inspect(blob: &[u8]) -> Result<BundleInfo, BundleError> {
    if blob.len() < DATA_OFFSET {
        return Err(BundleError::TooShort);
    }
    if &blob[..4] != MAGIC {
        return Err(BundleError::NotBundle);
    }
    let version = blob[4];
    if version != FORMAT_VERSION {
        return Err(BundleError::BadVersion(version));
    }
    let kdf = blob[5];
    if kdf != KDF_SCRYPT {
        return Err(BundleError::BadKdf(kdf));
    }
    let (n_log2, r, p) = (blob[6], blob[7], blob[8]);
    check_params(n_log2, r, p)?;
    Ok(BundleInfo {
        version,
        n_log2,
        r,
        p,
        ciphertext_size: blob.len() - DATA_OFFSET,
    })
}

pub fn seal(data: &[u8], password: &str, n_log2: u8) -> Result<Vec<u8>, BundleError> {
    if password.is_empty() {
        return Err(BundleError::EmptyPassword);
    }
    let r = DEFAULT_R;
    let p = DEFAULT_P;
    check_params(n_log2, r, p)?;

    let salt: [u8; SALT_SIZE] = random_bytes();
    let nonce: [u8; NONCE_SIZE] = random_bytes();

    let mut header = Vec::with_capacity(HEADER_SIZE);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&[FORMAT_VERSION, KDF_SCRYPT, n_log2, r, p]);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let (enc_key, mac_key) = derive(password, &salt, n_log2, r, p)?;
    let ciphertext = ctr_xor(&enc_key, &nonce, data);

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&mac_key).expect("HMAC 接受任意长度密钥");
    mac.update(&header);
    mac.update(&ciphertext);
    let mac_bytes = mac.finalize().into_bytes();

    let mut blob = Vec::with_capacity(DATA_OFFSET + ciphertext.len());
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&mac_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

pub fn unseal(blob: &[u8], password: &str) -> Result<Vec<u8>, BundleError> {
    let info = inspect(blob)?;
    if password.is_empty() {
        return Err(BundleError::EmptyPassword);
    }
    let salt: [u8; SALT_SIZE] = blob[9..9 + SALT_SIZE].try_into().expect("长度已校验");
    let nonce: [u8; NONCE_SIZE] = blob[9 + SALT_SIZE..HEADER_SIZE]
        .try_into()
        .expect("长度已校验");
    let mac_bytes = &blob[HEADER_SIZE..DATA_OFFSET];
    let ciphertext = &blob[DATA_OFFSET..];

    let (enc_key, mac_key) = derive(password, &salt, info.n_log2, info.r, info.p)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&mac_key).expect("HMAC 接受任意长度密钥");
    mac.update(&blob[..HEADER_SIZE]);
    mac.update(ciphertext);
    // 不区分"口令错"和"被篡改"：能区分就等于给出一次免费的爆破反馈
    mac.verify_slice(mac_bytes).map_err(|_| BundleError::Auth)?;

    Ok(ctr_xor(&enc_key, &nonce, ciphertext))
}
