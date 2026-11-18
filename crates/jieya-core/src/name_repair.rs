//! 修复解压出来的乱码文件名（ZIP 条目里的非 UTF-8 文件名）。
//!
//! ## 乱码从哪来
//!
//! ZIP 规范里条目文件名默认用「创建者所在系统的本地代码页」，只有 flag bit 11
//! （UTF-8 标志）置位时才保证是 UTF-8。日文资源包大量由 Shift-JIS 环境的工具
//! 生成，其中相当一部分既不置标志、又用 Shift-JIS 写名字。7z 在中文 Windows 上
//! 对这类条目按系统代码页 936（GBK）解释字节，落盘就成了：
//!
//! ```text
//! 日本語のファイル名.mp3  →  擔杮岅偺僼傽僀儖柤.mp3
//! ```
//!
//! 另一条来路是 AES-256 的 ZIP：7z 的 zip-AES 对非 ASCII 密码是坏的，由本程序
//! 自己解，而自己解时对没置 UTF-8 标志的名字按 CP437 解 —— 于是 GBK 中文名落盘
//! 成 `▒╗╤█╒╓┐╪…` 这种方框字。所以反推时两档源编码都要试：cp936 与 cp437。
//!
//! ## 怎么反推
//!
//! 主路径是**整包判一次编码**（见 [`detect_name_encoding`]）：把包内所有条目名
//! 当成一份样本，逐档严格解码，只有"一条都解不动都没有、一个可疑字符都没有"、
//! 且没有第二种字系也解得通的编码才算可信。判不出来就退回逐名启发式。
//!
//! 逐名启发式的原理是：乱码本身就是「原始字节被 GBK 解码」的结果，反推就是把它
//! 编码回字节、再按原编码严格解一次。严格模式是关键 —— UTF-8 的校验极严，GBK
//! 双字节几乎凑不出合法 UTF-8 序列。
//!
//! ## 为什么必须保守
//!
//! 把正常中文名改成日文乱码比不修更糟。所以两道硬闸门：名字本身要"看起来不像
//! 正常文本"，且修复结果不许比原样更差（垃圾分必须严格下降、不许新增半角假名）。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::zip_dir;

// ---------------------------------------------------------------------------
// CP437（encoding_rs 不收这一档，只能自带 256 项表）
// ---------------------------------------------------------------------------

/// 0x80..=0xFF 的字符表；0x00..=0x7F 直接是 ASCII
const CP437_HIGH: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', //
    'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', //
    'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', //
    '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐', //
    '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧', //
    '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀', //
    'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', //
    '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{a0}',
];

fn cp437_encode_table() -> &'static HashMap<char, u8> {
    static TABLE: OnceLock<HashMap<char, u8>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut map = HashMap::with_capacity(256);
        for b in 0x20u8..=0x7E {
            map.insert(b as char, b);
        }
        for (i, ch) in CP437_HIGH.iter().enumerate() {
            map.insert(*ch, 0x80 + i as u8);
        }
        map
    })
}

fn cp437_decode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if b < 0x80 {
            out.push(b as char);
        } else {
            out.push(CP437_HIGH[(b - 0x80) as usize]);
        }
    }
    out
}

fn cp437_encode(text: &str) -> Option<Vec<u8>> {
    let table = cp437_encode_table();
    let mut out = Vec::with_capacity(text.len());
    for ch in text.chars() {
        out.push(*table.get(&ch)?);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// 编码档位
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Codec {
    Utf8,
    Cp932,
    Gbk,
    Gb18030,
    EucJp,
    Cp437,
}

impl Codec {
    fn label(self) -> &'static str {
        match self {
            Codec::Utf8 => "UTF-8",
            Codec::Cp932 => "Shift-JIS",
            Codec::Gbk => "GBK",
            Codec::Gb18030 => "GB18030",
            Codec::EucJp => "EUC-JP",
            Codec::Cp437 => "CP437",
        }
    }

    fn family(self) -> &'static str {
        match self {
            Codec::Utf8 => "utf8",
            Codec::Cp932 | Codec::EucJp => "jp",
            Codec::Gbk | Codec::Gb18030 => "gb",
            Codec::Cp437 => "cp437",
        }
    }

    /// 严格解码：任何一处解不动就整条放弃。
    ///
    /// encoding_rs 的解码器不抛错而是插替换字符，所以用 `had_errors` 判断，
    /// 语义上等价于 Python 的 UnicodeDecodeError。
    fn decode(self, raw: &[u8]) -> Option<String> {
        if self == Codec::Cp437 {
            return Some(cp437_decode(raw));
        }
        let encoding = match self {
            Codec::Utf8 => encoding_rs::UTF_8,
            Codec::Cp932 => encoding_rs::SHIFT_JIS,
            Codec::Gbk | Codec::Gb18030 => encoding_rs::GBK,
            Codec::EucJp => encoding_rs::EUC_JP,
            Codec::Cp437 => unreachable!(),
        };
        let (cow, _, had_errors) = encoding.decode(raw);
        if had_errors {
            None
        } else {
            Some(cow.into_owned())
        }
    }

    /// 把文本编码回字节（启发式反推的第一步）；编不动返回 None。
    fn encode(self, text: &str) -> Option<Vec<u8>> {
        if self == Codec::Cp437 {
            return cp437_encode(text);
        }
        let encoding = match self {
            Codec::Utf8 => encoding_rs::UTF_8,
            Codec::Cp932 => encoding_rs::SHIFT_JIS,
            Codec::Gbk | Codec::Gb18030 => encoding_rs::GBK,
            Codec::EucJp => encoding_rs::EUC_JP,
            Codec::Cp437 => unreachable!(),
        };
        let (cow, _, had_unmappable) = encoding.encode(text);
        if had_unmappable {
            None
        } else {
            Some(cow.into_owned())
        }
    }
}

/// 判断顺序即优先级：utf-8 最严格、误判率最低；cp932 是日文 Windows 的实际编码；
/// gbk/gb18030 是中文包的实际编码；euc-jp 只用于少数 Unix 侧工具。
const TARGET_CODECS: [Codec; 5] = [
    Codec::Utf8,
    Codec::Cp932,
    Codec::Gbk,
    Codec::Gb18030,
    Codec::EucJp,
];

/// 磁盘上的乱码可能来自两档：7z 按 cp936 解坏，或 CP437 解坏（AES 包/英文系统）。
const SHOWN_CODECS: [Codec; 2] = [Codec::Gbk, Codec::Cp437];

/// 整包判定的候选（big5 故意不收：繁体字大量落在 GB2312 区外，会被自家指标冤枉）
const DETECT_CODECS: [Codec; 5] = [
    Codec::Utf8,
    Codec::Gbk,
    Codec::Gb18030,
    Codec::Cp932,
    Codec::EucJp,
];

const ILLEGAL: [char; 9] = ['\\', '/', ':', '*', '?', '"', '<', '>', '|'];

// ---------------------------------------------------------------------------
// 字符指标
// ---------------------------------------------------------------------------

/// 这个字符是否落在 GB2312 常用字/符号区（6763 个汉字 + 常用标点）。
///
/// encoding_rs 没有 GB2312 编码器，但 GB2312 ⊂ GBK：把字符编成 GBK 字节后看落点，
/// 汉字区 0xB0A1–0xF7FE、符号区 0xA1A1–0xA9FE 正是 GB2312 的范围，区外就是 GBK
/// 扩展，判为「非 GB2312」。
fn in_gb2312(ch: char) -> bool {
    if ch.is_ascii() {
        return true;
    }
    let s = ch.to_string();
    let (bytes, _, had_unmappable) = encoding_rs::GBK.encode(&s);
    if had_unmappable || bytes.len() != 2 {
        return false;
    }
    let (lead, trail) = (bytes[0], bytes[1]);
    ((0xB0..=0xF7).contains(&lead) && (0xA1..=0xFE).contains(&trail))
        || ((0xA1..=0xA9).contains(&lead) && (0xA1..=0xFE).contains(&trail))
}

/// 越大越不像正常文本。只用于「修复前后谁更差」的相对比较。
fn garbage_score(text: &str) -> i32 {
    let mut score = 0;
    for ch in text.chars() {
        let cp = ch as u32;
        match cp {
            0xFFFD => score += 30,
            0xFF61..=0xFF9F => score += 6,  // 半角假名
            0xE000..=0xF8FF => score += 10, // 私用区
            0xF900..=0xFAFF => score += 4,  // 兼容汉字
            0x3400..=0x4DBF => score += 2,  // 扩展 A
            0x20000.. => score += 3,        // 扩展 B 及以后
            0xAC00..=0xD7AF | 0x1100..=0x11FF => score += 3, // 谚文
            0x2500..=0x259F => score += 6,  // 制表符/方块
            _ => {
                if (0x4E00..=0x9FFF).contains(&cp) && !in_gb2312(ch) {
                    score += 2; // 生僻字：Shift-JIS/UTF-8 被按 GBK 解的典型落点
                }
            }
        }
    }
    score
}

/// (汉字数, GB2312 内汉字数, 全角假名数, 半角假名数)
fn counts(text: &str) -> (i32, i32, i32, i32) {
    let (mut han, mut common, mut kana, mut half) = (0, 0, 0, 0);
    for ch in text.chars() {
        let cp = ch as u32;
        if (0x4E00..=0x9FFF).contains(&cp) {
            han += 1;
            if in_gb2312(ch) {
                common += 1;
            }
        } else if (0x3040..=0x30FF).contains(&cp) {
            kana += 1;
        } else if (0xFF61..=0xFF9F).contains(&cp) {
            half += 1;
        }
    }
    (han, common, kana, half)
}

fn box_chars(text: &str) -> usize {
    text.chars()
        .filter(|c| (0x2500..=0x259F).contains(&(*c as u32)))
        .count()
}

/// 这个名字是否可能是「非本地区码的字节被按本地区码解」的产物。
/// 保守到近乎吝啬：false 只代表「不值得冒险去改」。
fn looks_like_mojibake(name: &str) -> bool {
    if name.is_empty() || name.is_ascii() {
        return false;
    }
    // 字节已经丢了（替换字符/半角 ?），怎么解都是猜
    if name.contains('\u{FFFD}') || name.contains('?') {
        return false;
    }
    if box_chars(name) >= 2 {
        return true;
    }
    let (han, common, kana, half) = counts(name);
    if half > 0 {
        return true;
    }
    if han == 0 {
        return false;
    }
    kana * 3 < han && common * 2 < han
}

fn structurally_ok(candidate: &str) -> bool {
    if candidate.is_empty() || candidate.contains('\u{FFFD}') {
        return false;
    }
    if candidate.chars().any(|c| ILLEGAL.contains(&c)) {
        return false;
    }
    if candidate.chars().any(|c| (c as u32) < 0x20) {
        return false;
    }
    !(candidate.ends_with(' ') || candidate.ends_with('.'))
}

fn plausible(candidate: &str, original: &str) -> bool {
    if candidate.is_empty() || candidate == original || !structurally_ok(candidate) {
        return false;
    }
    if garbage_score(candidate) >= garbage_score(original) {
        return false;
    }
    let (_, _, _, new_half) = counts(candidate);
    let (_, _, _, old_half) = counts(original);
    if new_half > old_half {
        return false;
    }
    let (han, common, kana, _) = counts(candidate);
    if han > 0 && kana == 0 && common * 2 < han {
        // 解出来还是生僻字堆，说明这一档编码不对
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// 逐名反推
//
// 不做缓存：单次任务里名字数量有限，缓存反而要跨线程共享状态；Python 侧的
// lru_cache 只是优化，不影响语义。
// ---------------------------------------------------------------------------

/// 修一个文件名（含扩展名整段处理），返回 (新名, 编码标签)。修不动原样返回。
pub fn repair_name_full(name: &str) -> (String, String) {
    if !looks_like_mojibake(name) {
        return (name.to_string(), String::new());
    }
    for source in [Codec::Gbk, Codec::Gb18030, Codec::Cp437] {
        let Some(raw) = source.encode(name) else {
            continue;
        };
        for codec in TARGET_CODECS {
            let Some(candidate) = codec.decode(&raw) else {
                continue;
            };
            if plausible(&candidate, name) {
                return (candidate, codec.label().to_string());
            }
        }
    }
    (name.to_string(), String::new())
}

pub fn repair_name(name: &str) -> String {
    repair_name_full(name).0
}

pub fn repair_encoding(name: &str) -> String {
    repair_name_full(name).1
}

/// 用**原始字节**解码：比逐名反推强，7z 插过替换字符时也能救回来。
fn repair_bytes(raw: &[u8], shown: &str) -> (String, String) {
    if !looks_like_mojibake(shown) {
        return (shown.to_string(), String::new());
    }
    for codec in TARGET_CODECS {
        let Some(candidate) = codec.decode(raw) else {
            continue;
        };
        if plausible(&candidate, shown) {
            return (candidate, codec.label().to_string());
        }
    }
    (shown.to_string(), String::new())
}

// ---------------------------------------------------------------------------
// 整包编码判定
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EncodingVerdict {
    pub codec: String,
    pub label: String,
    pub names: usize,
    pub confident: bool,
    pub margin: f32,
    pub reason: String,
    pub scores: Vec<(String, f32)>,
}

impl EncodingVerdict {
    pub fn describe(&self) -> String {
        if self.confident {
            format!(
                "{}（{} 条名字，领先次优 {:.2}）",
                self.label, self.names, self.margin
            )
        } else {
            format!(
                "判不准：{}",
                if self.reason.is_empty() {
                    "候选互不相让"
                } else {
                    &self.reason
                }
            )
        }
    }

    fn codec(&self) -> Option<Codec> {
        DETECT_CODECS
            .iter()
            .copied()
            .find(|c| c.label() == self.label)
    }
}

/// 单字符「不像正常文件名」的程度（0 = 正常）。
fn char_badness(ch: char) -> f32 {
    let cp = ch as u32;
    match cp {
        0xFFFD => 1.0,
        0..=0x1F => 1.0,
        0xE000..=0xF8FF => 1.0,
        0x2500..=0x259F => 1.0,
        0xFF61..=0xFF9F => 1.0,
        0xF900..=0xFAFF | 0x3400..=0x4DBF | 0x20000.. => 0.8,
        0xAC00..=0xD7AF => 0.6,
        _ => {
            if (0x4E00..=0x9FFF).contains(&cp) && !in_gb2312(ch) {
                0.45
            } else {
                0.0
            }
        }
    }
}

/// 中央目录里「没置 UTF-8 标志」的条目名，按 `/` 切段。
fn archive_plain_names(archive: &Path) -> Option<(Vec<Vec<u8>>, usize)> {
    let entries = zip_dir::read_entries(archive)?;
    let mut plain = Vec::new();
    for e in &entries {
        if e.flags & 0x800 != 0 {
            continue;
        }
        for seg in e.name_raw.split(|b| *b == b'/') {
            if seg.is_empty() || seg.contains(&b'\\') {
                continue;
            }
            plain.push(seg.to_vec());
        }
    }
    Some((plain, entries.len()))
}

/// 判定这个压缩包的文件名按哪种编码写。
///
/// 返回 None：不是 zip／没有条目名／打不开。判不准时 `confident=false`，
/// 调用方应退回逐名反推。
pub fn detect_name_encoding(archive: &Path, max_entries: usize) -> Option<EncodingVerdict> {
    let (plain, _total) = archive_plain_names(archive)?;
    if plain.is_empty() {
        return None;
    }
    let sample: Vec<&Vec<u8>> = plain.iter().take(max_entries).collect();

    let mut scores: HashMap<Codec, f32> = HashMap::new();
    let mut clean: HashMap<Codec, bool> = HashMap::new();
    for codec in DETECT_CODECS {
        let (mut fails, mut severe, mut rare, mut chars) = (0u32, 0u32, 0u32, 0u32);
        for seg in &sample {
            let Some(text) = codec.decode(seg) else {
                fails += 1;
                continue;
            };
            chars += text.chars().count() as u32;
            for ch in text.chars() {
                let weight = char_badness(ch);
                if weight >= 0.6 {
                    severe += 1;
                } else if weight > 0.0 {
                    rare += 1;
                }
            }
        }
        let score = if chars > 0 {
            (severe as f32 + rare as f32 * 0.45) / chars as f32
        } else {
            1.0
        };
        scores.insert(codec, score);
        clean.insert(codec, fails == 0 && chars > 0 && severe == 0 && rare * 20 <= chars);
    }

    let rank = |c: Codec| {
        DETECT_CODECS
            .iter()
            .position(|x| *x == c)
            .unwrap_or(usize::MAX)
    };
    let usable: Vec<Codec> = DETECT_CODECS
        .iter()
        .copied()
        .filter(|c| *clean.get(c).unwrap_or(&false))
        .collect();
    let names = sample.len();
    let table: Vec<(String, f32)> = {
        let mut sorted: Vec<(Codec, f32)> = DETECT_CODECS
            .iter()
            .map(|c| (*c, *scores.get(c).unwrap_or(&1.0)))
            .collect();
        sorted.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        sorted
            .into_iter()
            .map(|(c, s)| (c.label().to_string(), s))
            .collect()
    };

    if usable.is_empty() {
        let best = DETECT_CODECS
            .iter()
            .copied()
            .min_by(|a, b| {
                scores
                    .get(a)
                    .unwrap_or(&1.0)
                    .partial_cmp(scores.get(b).unwrap_or(&1.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(rank(*a).cmp(&rank(*b)))
            })
            .unwrap_or(Codec::Utf8);
        return Some(EncodingVerdict {
            codec: best.label().to_string(),
            label: best.label().to_string(),
            names,
            confident: false,
            margin: 0.0,
            reason: "各候选解出来都不干净".into(),
            scores: table,
        });
    }

    let best = usable
        .iter()
        .copied()
        .min_by(|a, b| {
            scores
                .get(a)
                .unwrap_or(&1.0)
                .partial_cmp(scores.get(b).unwrap_or(&1.0))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(rank(*a).cmp(&rank(*b)))
        })
        .unwrap_or(Codec::Utf8);
    let best_family = best.family();
    let rivals: Vec<f32> = DETECT_CODECS
        .iter()
        .filter(|c| c.family() != best_family)
        .map(|c| *scores.get(c).unwrap_or(&1.0))
        .collect();
    let margin = rivals
        .iter()
        .copied()
        .fold(None::<f32>, |acc, v| Some(acc.map_or(v, |a| a.min(v)))
        )
        .map(|m| m - scores.get(&best).copied().unwrap_or(1.0))
        .unwrap_or(1.0);

    let other = usable.iter().any(|c| c.family() != best_family);
    if other {
        return Some(EncodingVerdict {
            codec: best.label().to_string(),
            label: best.label().to_string(),
            names,
            confident: false,
            margin,
            reason: "两个字系都解得通，分辨不了".into(),
            scores: table,
        });
    }
    Some(EncodingVerdict {
        codec: best.label().to_string(),
        label: best.label().to_string(),
        names,
        confident: true,
        margin,
        reason: String::new(),
        scores: table,
    })
}

/// 这一条名字最终该叫什么。
fn decode_segment(raw: &[u8], shown: &str, verdict: Option<&EncodingVerdict>) -> (String, String) {
    if let Some(v) = verdict {
        if v.confident {
            let Some(codec) = v.codec() else {
                return repair_bytes(raw, shown);
            };
            let Some(candidate) = codec.decode(raw) else {
                return repair_bytes(raw, shown); // 混合编码的条目交给逐名逻辑
            };
            if candidate == shown {
                return (shown.to_string(), String::new()); // 本来就是这档：一个字别动
            }
            if structurally_ok(&candidate) && garbage_score(&candidate) <= garbage_score(shown) {
                return (candidate, v.label.clone());
            }
            return (shown.to_string(), String::new());
        }
    }
    repair_bytes(raw, shown)
}

// ---------------------------------------------------------------------------
// 树修复
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct NameRepair {
    pub renamed: usize,
    pub encoding: String,
    pub samples: Vec<(String, String)>,
    pub verdict: Option<EncodingVerdict>,
}

impl NameRepair {
    /// 给界面列用的最短一句：只讲"修了几个"。
    pub fn summary(&self) -> String {
        if self.renamed == 0 {
            String::new()
        } else {
            format!("已修正 {} 个乱码文件名", self.renamed)
        }
    }

    /// 带编码与例子的一句，给 CLI / tooltip 这种有横向空间的地方。
    pub fn describe(&self) -> String {
        let mut head = self.summary();
        if head.is_empty() {
            return head;
        }
        if !self.encoding.is_empty() {
            head.push_str(&format!("（{}）", self.encoding));
        }
        if let Some((old, new)) = self.samples.first() {
            head.push_str(&format!("，例如 {} → {}", old, new));
        }
        head
    }
}

struct Planned {
    depth: usize,
    path: PathBuf,
    new_name: String,
    old_name: String,
    label: String,
}

/// 目标已存在就挪后缀，绝不覆盖。
fn unique_target(parent: &Path, name: &str) -> Option<PathBuf> {
    let target = parent.join(name);
    if !target.exists() {
        return Some(target);
    }
    let path = Path::new(name);
    let stem = path.file_stem().map(|s| s.to_string_lossy().to_string())?;
    let suffix = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    for index in 2..1000 {
        let candidate = parent.join(format!("{stem} ({index}){suffix}"));
        if !candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn bump(result: &mut NameRepair, encodings: &mut HashMap<String, usize>, old: &str, new: &str, label: &str) {
    result.renamed += 1;
    if !label.is_empty() {
        *encodings.entry(label.to_string()).or_insert(0) += 1;
    }
    if result.samples.len() < 5 {
        result.samples.push((old.to_string(), new.to_string()));
    }
}

fn plan_from_zip(archive: &Path, root: &Path, verdict: Option<&EncodingVerdict>) -> Vec<Planned> {
    let Some(entries) = zip_dir::read_entries(archive) else {
        return Vec::new(); // 7z/rar、分卷首卷、包损坏：这条路不适用
    };
    let mut planned = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for e in &entries {
        if e.flags & 0x800 != 0 {
            continue; // 带 UTF-8 标志：7z 本来就解对了
        }
        let segments: Vec<&[u8]> = e
            .name_raw
            .split(|b| *b == b'/')
            .filter(|s| !s.is_empty() && !s.contains(&b'\\'))
            .collect();
        if segments.is_empty() {
            continue;
        }
        for shown_codec in SHOWN_CODECS {
            // 磁盘上的名字是哪一档解出来的？用真实路径反查，而不是假定 cp936
            let Some(old_parts) = segments
                .iter()
                .map(|seg| shown_codec.decode(seg))
                .collect::<Option<Vec<String>>>()
            else {
                continue;
            };
            let old_rel = old_parts.join(std::path::MAIN_SEPARATOR_STR);
            if seen.contains(&old_rel) {
                break;
            }
            if !root.join(&old_rel).exists() {
                continue; // 这一档对不上磁盘，试下一档
            }
            seen.insert(old_rel.clone());

            let mut new_parts = Vec::with_capacity(segments.len());
            let mut label = String::new();
            for (seg, shown) in segments.iter().zip(old_parts.iter()) {
                let (fixed, seg_label) = decode_segment(seg, shown, verdict);
                new_parts.push(fixed);
                if !seg_label.is_empty() {
                    label = seg_label;
                }
            }
            // 只改当前这一级；父目录留给深度更小的那一轮（父改名后子项自动跟过去）
            planned.push(Planned {
                depth: segments.len(),
                path: root.join(&old_rel),
                new_name: new_parts.last().cloned().unwrap_or_default(),
                old_name: old_parts.last().cloned().unwrap_or_default(),
                label,
            });
            break;
        }
    }
    planned
}

fn from_zip(archive: &Path, root: &Path, result: &mut NameRepair, encodings: &mut HashMap<String, usize>) {
    let mut planned = plan_from_zip(archive, root, result.verdict.as_ref());
    planned.sort_by(|a, b| b.depth.cmp(&a.depth)); // 深度降序：先改深层
    for item in planned {
        if item.new_name == item.old_name || item.new_name.is_empty() {
            continue;
        }
        let Some(parent) = item.path.parent() else {
            continue;
        };
        if !parent.is_dir() || !item.path.exists() {
            continue;
        }
        let Some(target) = unique_target(parent, &item.new_name) else {
            continue;
        };
        if std::fs::rename(&item.path, &target).is_ok() {
            bump(result, encodings, &item.old_name, &item.new_name, &item.label);
        }
    }
}

/// 兜底：不依赖压缩包，直接从磁盘上的乱码名反推。
///
/// 必须先收集、再按深度降序处理：边遍历边改名会让父级那一轮拿到旧名，
/// 接着对旧路径 rename 就会失败（异常被吞掉就是"有些目录没修"）。
fn from_heuristic(root: &Path, result: &mut NameRepair, encodings: &mut HashMap<String, usize>, limit: usize) {
    let mut entries: Vec<(usize, PathBuf)> = Vec::new();
    collect_entries(root, root, &mut entries, limit);
    entries.sort_by(|a, b| b.0.cmp(&a.0));

    for (_, path) in entries {
        let Some(parent) = path.parent() else {
            continue;
        };
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let (new_name, label) = repair_name_full(&name);
        if new_name == name || new_name.is_empty() {
            continue;
        }
        if !parent.is_dir() || !path.exists() {
            continue;
        }
        let Some(target) = unique_target(parent, &new_name) else {
            continue;
        };
        if std::fs::rename(&path, &target).is_ok() {
            bump(result, encodings, &name, &new_name, &label);
        }
    }
}

fn collect_entries(root: &Path, dir: &Path, out: &mut Vec<(usize, PathBuf)>, limit: usize) {
    if out.len() > limit {
        return;
    }
    let depth = dir
        .strip_prefix(root)
        .map(|p| p.components().count())
        .unwrap_or(0);
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut subdirs = Vec::new();
    for entry in rd.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() {
            out.push((depth, path.clone()));
            subdirs.push(path);
        } else {
            out.push((depth, path));
        }
    }
    for sub in subdirs {
        collect_entries(root, &sub, out, limit);
    }
}

/// 把 root 之下所有乱码名改回来。
///
/// 两条路，先确定后启发：ZIP 中央目录能精确还原（原始字节能救回被替换字符毁掉的
/// 名字），启发式收拾残余（7z/rar、分卷、包内自带的乱码目录项）。
pub fn repair_tree(root: &Path, archive: Option<&Path>, limit: usize) -> NameRepair {
    let mut result = NameRepair::default();
    if !root.is_dir() {
        return result;
    }
    let mut encodings: HashMap<String, usize> = HashMap::new();
    if let Some(archive) = archive {
        result.verdict = detect_name_encoding(archive, 4000);
        from_zip(archive, root, &mut result, &mut encodings);
    }
    from_heuristic(root, &mut result, &mut encodings, limit);
    if let Some((label, _)) = encodings.iter().max_by_key(|(_, v)| *v) {
        result.encoding = label.clone();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_chinese_name_is_not_touched() {
        assert!(!looks_like_mojibake("中文文件名.txt"));
        assert_eq!(repair_name("中文文件名.txt"), "中文文件名.txt");
    }

    #[test]
    fn shift_jis_mojibake_is_recognized() {
        // 日本語のファイル名.mp3 被按 GBK 解的产物
        let broken = "擔杮岅偺僼傽僀儖柤.mp3";
        assert!(looks_like_mojibake(broken));
        let fixed = repair_name(broken);
        assert!(fixed.contains("日本語"), "got {fixed}");
    }

    #[test]
    fn cp437_boxes_are_recognized() {
        let broken = "▒╗╤█╒╓┐╪";
        assert!(looks_like_mojibake(broken));
    }

    #[test]
    fn cp437_roundtrip() {
        let bytes = b"\xC3\xD8\xC3\xDC.TXT";
        let shown = cp437_decode(bytes);
        assert_eq!(shown.chars().count(), 8);
        assert_eq!(cp437_encode(&shown), Some(bytes.to_vec()));
    }

    #[test]
    fn gb2312_range_check() {
        assert!(in_gb2312('中'));
        assert!(in_gb2312('a'));
        assert!(!in_gb2312('€'));
    }

    // ---- 端到端：造一个 Shift-JIS 名的 ZIP，磁盘上放 GBK 解出来的乱码名 ----

    fn build_zip(path: &Path, entries: &[(&[u8], &[u8])]) -> std::io::Result<()> {
        use std::io::Write;
        let mut locals: Vec<u8> = Vec::new();
        let mut centrals: Vec<u8> = Vec::new();
        for (raw_name, payload) in entries {
            let offset = locals.len() as u32;
            let crc = crc32fast::hash(payload);
            let mut local = Vec::new();
            local.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
            local.extend_from_slice(&20u16.to_le_bytes()); // version
            local.extend_from_slice(&0u16.to_le_bytes()); // flags：不置 UTF-8
            local.extend_from_slice(&0u16.to_le_bytes()); // method=store
            local.extend_from_slice(&0u16.to_le_bytes()); // time
            local.extend_from_slice(&0u16.to_le_bytes()); // date
            local.extend_from_slice(&crc.to_le_bytes());
            local.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            local.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            local.extend_from_slice(&(raw_name.len() as u16).to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(raw_name);
            local.extend_from_slice(payload);
            locals.extend_from_slice(&local);

            let mut central = Vec::new();
            central.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            central.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            central.extend_from_slice(&(raw_name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // extra
            central.extend_from_slice(&0u16.to_le_bytes()); // comment
            central.extend_from_slice(&0u16.to_le_bytes()); // disk
            central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(raw_name);
            centrals.extend_from_slice(&central);
        }
        let mut out = locals;
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&centrals);
        out.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(centrals.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        std::fs::write(path, out)
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "jieya_test_{tag}_{}",
            std::process::id() as u64 * 1000 + std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64 % 1000)
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn shift_jis_zip_names_are_repaired_from_central_directory() {
        let dir = temp_dir("sjis");
        let archive = dir.join("日文包.zip");
        let name = "日本語のファイル名.mp3";
        let raw = Codec::Cp932.encode(name).unwrap();
        build_zip(&archive, &[(raw.as_slice(), b"fixture\n")]).unwrap();

        // 磁盘上是 7z 按 GBK 解出来的乱码名
        let broken = Codec::Gbk.decode(&raw).unwrap();
        let out = dir.join("日文包");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join(&broken), b"fixture\n").unwrap();

        let verdict = detect_name_encoding(&archive, 4000).unwrap();
        // 单条目样本不足以判「可信」（原版同样保守）；即便不可信，逐名反推也要修好
        assert_eq!(verdict.label, "Shift-JIS", "{verdict:?}");

        let result = repair_tree(&out, Some(&archive), 200_000);
        assert_eq!(result.renamed, 1, "{result:?}");
        assert_eq!(result.encoding, "Shift-JIS");
        assert!(out.join(name).exists(), "修复后的名字应当落盘");
        assert!(!out.join(&broken).exists(), "乱码名应当改掉");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn correct_gbk_names_are_left_alone() {
        let dir = temp_dir("gbk");
        let archive = dir.join("中文包.zip");
        let name = "中文文件名.txt";
        let raw = Codec::Gbk.encode(name).unwrap();
        build_zip(&archive, &[(raw.as_slice(), b"fixture\n")]).unwrap();

        let out = dir.join("中文包");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join(name), b"fixture\n").unwrap();

        let result = repair_tree(&out, Some(&archive), 200_000);
        assert_eq!(result.renamed, 0, "{result:?}");
        assert!(out.join(name).exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nested_directory_and_file_both_repair() {
        let dir = temp_dir("nested");
        let archive = dir.join("包.zip");
        let dir_name = "フォルダ";
        let file_name = "中のファイル.txt";
        let raw_dir = Codec::Cp932.encode(dir_name).unwrap();
        let raw_file = Codec::Cp932.encode(file_name).unwrap();
        build_zip(
            &archive,
            &[
                (&raw_dir, b""),
                (
                    &[raw_dir.as_slice(), b"/", raw_file.as_slice()].concat(),
                    b"fixture\n",
                ),
            ],
        )
        .unwrap();

        let out = dir.join("包");
        std::fs::create_dir_all(&out).unwrap();
        let broken_dir = Codec::Gbk.decode(&raw_dir).unwrap();
        let broken_file = Codec::Gbk.decode(&raw_file).unwrap();
        std::fs::create_dir_all(out.join(&broken_dir)).unwrap();
        std::fs::write(out.join(&broken_dir).join(&broken_file), b"fixture\n").unwrap();

        let result = repair_tree(&out, Some(&archive), 200_000);
        assert_eq!(result.renamed, 2, "{result:?}");
        assert!(out.join(dir_name).join(file_name).exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}

