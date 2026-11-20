use std::path::PathBuf;

/// 一个压缩包条目的精简描述（只保留界面与分析要用的字段）。
#[derive(Debug, Clone, Default)]
pub struct ArchiveEntry {
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
    /// 该条目是否加密（7z/RAR 可逐条加密，不能只看整包标志）
    pub encrypted: bool,
}

/// 一次探测的结论：格式、体量、加密与分卷信息。
#[derive(Debug, Clone, Default)]
pub struct ArchiveInfo {
    pub path: PathBuf,
    pub format_name: String,
    pub dir_count: usize,
    pub file_count: usize,
    pub total_uncompressed: u64,
    /// 包体大小：分卷包为整组之和，见 detect::volume_group_total
    pub archive_size: u64,
    pub volume_count: usize,
    pub flag_encrypted: bool,
    /// 头部加密的包空密码列不出目录
    pub needs_password_for_listing: bool,
    pub entries: Vec<ArchiveEntry>,
}

impl ArchiveInfo {
    pub fn compression_ratio(&self) -> f64 {
        if self.archive_size == 0 {
            return 0.0;
        }
        self.total_uncompressed as f64 / self.archive_size as f64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Pending,
    Probing,
    Extracting,
    Done,
    Skipped,
    NeedsPassword,
    Failed,
}

impl TaskStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskStatus::Pending => "pending",
            TaskStatus::Probing => "probing",
            TaskStatus::Extracting => "extracting",
            TaskStatus::Done => "done",
            TaskStatus::Skipped => "skipped",
            TaskStatus::NeedsPassword => "needs_password",
            TaskStatus::Failed => "failed",
        }
    }

    pub fn from_str(s: &str) -> TaskStatus {
        match s {
            "pending" => TaskStatus::Pending,
            "probing" => TaskStatus::Probing,
            "extracting" => TaskStatus::Extracting,
            "done" => TaskStatus::Done,
            "skipped" => TaskStatus::Skipped,
            "needs_password" => TaskStatus::NeedsPassword,
            _ => TaskStatus::Failed,
        }
    }

    /// 状态机：与原版 models._TRANSITIONS 一致，非法迁移必须报错而不是照写。
    pub fn can_transition(self, next: TaskStatus) -> bool {
        use TaskStatus::*;
        if self == next {
            return true;
        }
        match self {
            Pending => matches!(next, Probing | Failed),
            Probing => matches!(next, Extracting | NeedsPassword | Failed),
            Extracting => matches!(next, Done | NeedsPassword | Failed),
            NeedsPassword => matches!(next, Extracting | Failed),
            Done => false,
            Skipped => false,
            Failed => matches!(next, Pending), // 允许手动重试
        }
    }

    pub fn require_transition(self, next: TaskStatus) -> crate::Result<()> {
        if self.can_transition(next) {
            Ok(())
        } else {
            Err(crate::Error::Other(format!(
                "非法状态迁移: {} -> {}",
                self.as_str(),
                next.as_str()
            )))
        }
    }
}

/// 与原版一致的本地时间戳（秒精度 ISO 8601，不带时区后缀）。
pub fn now_iso() -> String {
    chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string()
}

/// 递归流水线里的一个解压任务。id 从 1 递增，父任务 id 记录来源层级。
#[derive(Debug, Clone)]
pub struct Task {
    pub id: u64,
    pub archive: PathBuf,
    pub depth: u32,
    pub parent_id: Option<u64>,
    pub status: TaskStatus,
    pub password: Option<String>,
    pub out_dir: Option<PathBuf>,
    pub final_dir: Option<PathBuf>,
    pub error: Option<String>,
    pub info: Option<ArchiveInfo>,
    /// 包指纹（原版用于幂等判定；当前只做持久化字段，算法待接）
    pub archive_fingerprint: String,
    /// 交付失败原因：非空即「产物还压在暂存区」，清理时必须保留
    pub delivery_error: String,
}

impl Task {
    pub fn new(id: u64, archive: PathBuf, depth: u32, parent_id: Option<u64>) -> Self {
        Self {
            id,
            archive,
            depth,
            parent_id,
            status: TaskStatus::Pending,
            password: None,
            out_dir: None,
            final_dir: None,
            error: None,
            info: None,
            archive_fingerprint: String::new(),
            delivery_error: String::new(),
        }
    }
}
