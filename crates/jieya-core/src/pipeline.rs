use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::config::Config;
use crate::detect::{self, COMPOUND_ZIP_EXTS, VIDEO_EXTS};
use crate::error::{Error, Result};
use crate::models::{Task, TaskStatus};
use crate::output::{self, OutputMode, OutputPlan};
use crate::password::{self, build_candidates};
use crate::probe;
use crate::sevenzip::SevenZip;
use crate::store::TaskStore;
use crate::vault::Vault;
use crate::zip_crypto;

#[derive(Debug, Clone)]
pub enum Event {
    TaskStarted {
        task_id: u64,
        archive: PathBuf,
        depth: u32,
    },
    TaskInfo {
        task_id: u64,
        format: String,
        archive_size: u64,
        total_uncompressed: u64,
        file_count: usize,
        encrypted: bool,
        volumes: usize,
    },
    /// 阶段提示（算校验值、试第 N 个密码…）
    Phase {
        task_id: u64,
        message: String,
    },
    Progress {
        task_id: u64,
        percent: u8,
    },
    TaskDone {
        task_id: u64,
        archive: PathBuf,
        out_dir: PathBuf,
    },
    TaskSkipped {
        task_id: u64,
        archive: PathBuf,
        reason: String,
    },
    TaskFailed {
        task_id: u64,
        archive: PathBuf,
        reason: String,
    },
    NestedFound {
        task_id: u64,
        archive: PathBuf,
    },
    /// 解压后修正了乱码文件名（对应原版 name_repair 的 notice）
    NameRepaired {
        task_id: u64,
        count: usize,
        encoding: String,
        sample: Option<(String, String)>,
    },
    /// 非任务级告警（缺首卷、跳过的分卷组…）
    Warning {
        task_id: Option<u64>,
        message: String,
    },
}

#[derive(Debug, Default)]
pub struct RunReport {
    pub tasks: Vec<Task>,
    pub extracted: usize,
    pub failed: usize,
    pub skipped: usize,
    pub needs_password: usize,
    pub warnings: Vec<String>,
}

enum Attempt {
    Success { password: Option<String> },
    NeedsPassword { last_msg: String },
    Failed { msg: String },
    Cancelled,
}

pub struct Pipeline {
    pub cfg: Config,
    pub sz: SevenZip,
    pub vault: Option<Vault>,
    /// 任务历史（与密码库同一个 jieya.db，表结构同原版）。打开失败不影响解压。
    store: Option<Mutex<TaskStore>>,
    /// 是否跳过历史上已 DONE 的同路径任务（默认关：CLI 反复验证时不该被跳过）
    pub skip_done: bool,
    /// 顶层产物的目标父目录；None 表示解到压缩包旁边
    destination: Option<PathBuf>,
    /// 用户在界面上手动输入的密码（只对本次运行有效）
    manual_password: Option<String>,
}

impl Pipeline {
    pub fn new(cfg: Config) -> Self {
        let sz = SevenZip::new(
            cfg.sevenzip_path.clone(),
            cfg.list_timeout_secs,
            cfg.extract_timeout_secs,
        );
        let vault = Vault::open(&cfg.vault_path).ok();
        let store = TaskStore::open(&cfg.vault_path).ok().map(Mutex::new);
        Self {
            cfg,
            sz,
            vault,
            store,
            skip_done: false,
            destination: None,
            manual_password: None,
        }
    }

    pub fn with_sevenzip(cfg: Config, sz: SevenZip) -> Self {
        let vault = Vault::open(&cfg.vault_path).ok();
        let store = TaskStore::open(&cfg.vault_path).ok().map(Mutex::new);
        Self {
            cfg,
            sz,
            vault,
            store,
            skip_done: false,
            destination: None,
            manual_password: None,
        }
    }

    /// 指定顶层输出目录（右键「解压到指定目录」用）
    pub fn set_destination(&mut self, dest: Option<PathBuf>) {
        self.destination = dest.filter(|p| !p.as_os_str().is_empty());
    }

    /// 手动指定一个候选密码（界面输入，优先于密码库候选）
    pub fn set_password(&mut self, password: Option<String>) {
        self.manual_password = password.filter(|p| !p.is_empty());
    }

    fn persist_create(&self, task: &mut Task, source: &str) {
        let Some(store) = &self.store else {
            return;
        };
        let Ok(mut guard) = store.lock() else {
            return;
        };
        if let Err(e) = guard.create(task, source) {
            eprintln!("任务入库失败: {e}");
        }
    }

    fn persist_update(&self, task: &Task) {
        let Some(store) = &self.store else {
            return;
        };
        let Ok(mut guard) = store.lock() else {
            return;
        };
        if let Err(e) = guard.update(task) {
            eprintln!("任务状态写库失败: {e}");
        }
    }

    fn already_done(&self, path: &Path) -> bool {
        if !self.skip_done {
            return false;
        }
        let Some(store) = &self.store else {
            return false;
        };
        let Ok(guard) = store.lock() else {
            return false;
        };
        guard
            .find_done(&path.to_string_lossy())
            .ok()
            .flatten()
            .is_some()
    }

    /// BFS 递归解压：外层先解，产出的内层包入队，直到没有新包或到深度上限。
    pub fn run<F: Fn(Event)>(
        &self,
        inputs: &[PathBuf],
        mode: OutputMode,
        on_event: &F,
    ) -> Result<RunReport> {
        let mut report = RunReport::default();
        let mut queue: VecDeque<Task> = VecDeque::new();

        let inputs = self.collapse_volumes(self.collect(inputs), on_event, &mut report);
        for path in inputs {
            if probe::is_non_first_volume(&path) {
                continue;
            }
            if self.already_done(&path) {
                let mut skipped = Task::new(0, path, 0, None);
                skipped.status = TaskStatus::Skipped;
                skipped.error = Some("历史记录显示已解压完成".into());
                self.persist_create(&mut skipped, "");
                report.skipped += 1;
                report.tasks.push(skipped);
                continue;
            }
            let mut task = Task::new(0, path, 0, None);
            self.persist_create(&mut task, "");
            queue.push_back(task);
        }

        while let Some(mut task) = queue.pop_front() {
            task.status = TaskStatus::Probing;
            self.persist_update(&task);
            on_event(Event::TaskStarted {
                task_id: task.id,
                archive: task.archive.clone(),
                depth: task.depth,
            });

            // 内层分卷可能被外层包解到了别的目录：先把同组卷放到首卷旁边，
            // 否则 7z 只看到孤零零的首卷，报「不可预料的档案文件末端」。
            let joined = self.join_sibling_volumes(&task, &report.tasks);

            // 0. 视频/SFX 里内嵌的 ZIP：把 [start, end) 复制出来当真正的包，
            //    否则 7z 会对着 "mp4 头 + zip + 假尾部" 认错格式。
            let progress = |pct: u8| {
                on_event(Event::Phase {
                    task_id: task.id,
                    message: format!("正在恢复视频内嵌 ZIP… {pct}%"),
                })
            };
            let mut recovered: Option<crate::embedded::Recovered> = None;
            // 视频内嵌 ZIP 的临时副本优先放在目标盘（跨盘时不会把几个 G 塞进 C 盘），
            // 用完即删；普通压缩包走不到这里，直接写目标目录。
            let temp_root = {
                let anchor = self
                    .destination
                    .as_deref()
                    .map(|p| p.to_path_buf())
                    .or_else(|| task.archive.parent().map(|p| p.to_path_buf()))
                    .unwrap_or_else(|| self.cfg.workdir.clone());
                output::staging_root(&self.cfg.workdir, &anchor)
            };
            let actual: PathBuf = match crate::embedded::prepare(
                &task.archive,
                &temp_root,
                None,
                Some(&progress),
            ) {
                Ok(Some(r)) => {
                    let path = r.path().to_path_buf();
                    on_event(Event::Phase {
                        task_id: task.id,
                        message: "已识别视频内嵌 ZIP，正在按真实边界解压".into(),
                    });
                    recovered = Some(r);
                    path
                }
                Ok(None) => task.archive.clone(),
                Err(_) => task.archive.clone(),
            };

            // 1. 探测：拿到格式/大小/加密标记，供界面与 zip bomb 判定
            match probe::probe(&self.sz, &actual) {
                Ok(info) => {
                    on_event(Event::TaskInfo {
                        task_id: task.id,
                        format: info.format_name.clone(),
                        archive_size: info.archive_size,
                        total_uncompressed: info.total_uncompressed,
                        file_count: info.file_count,
                        encrypted: info.flag_encrypted,
                        volumes: info.volume_count,
                    });
                    if let Some(reason) = probe::check_bomb(&info, &self.cfg) {
                        task.status = TaskStatus::Failed;
                        task.error = Some(reason.clone());
                        self.persist_update(&task);
                        on_event(Event::TaskFailed {
                            task_id: task.id,
                            archive: task.archive.clone(),
                            reason,
                        });
                        report.failed += 1;
                        report.tasks.push(task);
                        continue;
                    }
                    task.info = Some(info);
                }
                Err(e) => {
                    task.status = TaskStatus::Failed;
                    task.error = Some(e.to_string());
                    self.persist_update(&task);
                    on_event(Event::TaskFailed {
                        task_id: task.id,
                        archive: task.archive.clone(),
                        reason: e.to_string(),
                    });
                    report.failed += 1;
                    report.tasks.push(task);
                    continue;
                }
            }

            // 2. 落点决策
            let parent_out = task
                .parent_id
                .and_then(|pid| report.tasks.iter().find(|t| t.id == pid))
                .and_then(|t| t.out_dir.clone());
            let plan: OutputPlan = output::plan_output(
                &task.archive,
                task.depth,
                task.id,
                mode,
                &self.cfg.workdir,
                parent_out.as_deref(),
                self.cfg.overwrite_existing,
                self.destination.as_deref(),
            );

            // 3. 解压（空密码 + 候选密码）
            task.status = TaskStatus::Extracting;
            self.persist_update(&task);
            let attempt = self.attempt_extract(&task, &actual, &plan.out_dir, on_event);

            match attempt {
                Attempt::Success { password } => {
                    task.status = TaskStatus::Done;
                    task.password = password;
                    task.out_dir = Some(plan.out_dir.clone());
                    task.final_dir = plan.final_dir.clone();
                    report.extracted += 1;

                    if plan.copy_back {
                        if let Some(final_dir) = &plan.final_dir {
                            deliver(&plan.out_dir, final_dir);
                            task.out_dir = Some(final_dir.clone());
                        }
                    }

                    let out_dir = task.out_dir.clone().unwrap_or(plan.out_dir.clone());

                    // 乱码文件名必须在产物交付/内层探测之前改回来：一旦按乱码名
                    // 交付出去，用户拿到的就是一堆认不出的文件。
                    let repair = crate::name_repair::repair_tree(
                        &out_dir,
                        Some(&actual),
                        200_000,
                    );
                    if repair.renamed > 0 {
                        on_event(Event::NameRepaired {
                            task_id: task.id,
                            count: repair.renamed,
                            encoding: repair.encoding.clone(),
                            sample: repair.samples.first().cloned(),
                        });
                    }

                    self.persist_update(&task);
                    on_event(Event::TaskDone {
                        task_id: task.id,
                        archive: task.archive.clone(),
                        out_dir: out_dir.clone(),
                    });

                    if task.depth < self.cfg.max_depth {
                        for nested in self.find_nested(&out_dir) {
                            on_event(Event::NestedFound {
                                task_id: task.id,
                                archive: nested.clone(),
                            });
                            let mut child =
                                Task::new(0, nested, task.depth + 1, Some(task.id));
                            self.persist_create(&mut child, "");
                            queue.push_back(child);
                        }
                    }

                    // 内层包是中间产物：解完就把本体删掉，只留内容。
                    // 内嵌 ZIP 是从视频里复制出来的临时副本，原视频绝不能删。
                    if task.depth > 0 && self.cfg.delete_intermediate && recovered.is_none() {
                        let _ = std::fs::remove_file(&task.archive);
                    }
                }
                Attempt::NeedsPassword { last_msg } => {
                    task.status = TaskStatus::NeedsPassword;
                    task.error = Some(if last_msg.is_empty() {
                        "需要密码（候选全部未命中）".into()
                    } else {
                        last_msg
                    });
                    report.needs_password += 1;
                    let reason = task.error.clone().unwrap_or_default();
                    self.persist_update(&task);
                    on_event(Event::TaskFailed {
                        task_id: task.id,
                        archive: task.archive.clone(),
                        reason,
                    });
                }
                Attempt::Failed { msg } => {
                    task.status = TaskStatus::Failed;
                    task.error = Some(msg.clone());
                    self.persist_update(&task);
                    on_event(Event::TaskFailed {
                        task_id: task.id,
                        archive: task.archive.clone(),
                        reason: msg,
                    });
                    report.failed += 1;
                }
                Attempt::Cancelled => {
                    task.status = TaskStatus::Failed;
                    task.error = Some("已取消".into());
                    self.persist_update(&task);
                    report.failed += 1;
                }
            }

            // 归并出来的链接是临时脚手架：解完立刻拆掉，不留垃圾
            for p in joined {
                let _ = std::fs::remove_file(&p);
            }

            report.tasks.push(task);
        }

        Ok(report)
    }

    /// 一次完整尝试：空密码 → 文件名/来源/密码库/字典候选。
    ///
    /// ZIP 先走两条快速路径：
    /// - **ZipCrypto 预筛**：只据此排除明显错误的候选，命中仍需真实解压验证；
    /// - **WinZip-AES 进程内解密**：2 字节校验值是权威判据，通过就直接解，
    ///   不再让 7z 浪费时间（它对非 ASCII 密码的 AES 路径是坏的）。
    fn attempt_extract<F: Fn(Event)>(
        &self,
        task: &Task,
        archive: &Path,
        out_dir: &Path,
        on_event: &F,
    ) -> Attempt {
        let file_name = task
            .archive
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let source = password::extract_source(&file_name);
        let vault_candidates = self
            .vault
            .as_ref()
            .and_then(|v| v.candidates_for(&source, self.cfg.max_password_attempts).ok())
            .unwrap_or_default();
        let candidates = build_candidates(&file_name, &source, &vault_candidates);

        // 避免与空密码或重复候选撞车
        let mut attempts: Vec<String> = vec![String::new()];
        if let Some(p) = &self.manual_password {
            if !attempts.contains(p) {
                attempts.push(p.clone());
            }
        }
        for c in &candidates {
            if !attempts.contains(c) {
                attempts.push(c.clone());
            }
        }
        let total = attempts.len().saturating_sub(1);

        let filter = zip_crypto::make_filter(archive);
        let aes_entries = zip_crypto::scan(archive);
        let mut last_msg = String::new();
        let mut skipped_by_filter = 0usize;
        let mut index = 0usize;

        while index < attempts.len() {
            let pwd = attempts[index].clone();
            index += 1;

            if let (Some(f), false) = (&filter, pwd.is_empty()) {
                // 空密码不用预筛，永远真实试一次
                let _ = f;
            }
            if !pwd.is_empty() {
                if let Some(f) = &filter {
                    if !f.may_match(&pwd) {
                        skipped_by_filter += 1;
                        continue;
                    }
                }
            }

            let task_id = task.id;
            let progress = |pct: u8| {
                on_event(Event::Progress {
                    task_id,
                    percent: pct,
                })
            };

            // AES 快速路径
            if let Some(entries) = &aes_entries {
                if zip_crypto::verify(entries, &pwd) {
                    on_event(Event::Phase {
                        task_id,
                        message: format!(
                            "AES 校验通过，进程内解密（{}）",
                            if pwd.is_empty() { "空密码" } else { "候选密码" }
                        ),
                    });
                    match zip_crypto::extract(
                        archive,
                        out_dir,
                        &pwd,
                        entries,
                        Some(&progress),
                        None,
                    ) {
                        Ok(_) => {
                            self.record_hit(&pwd, &source);
                            return Attempt::Success {
                                password: if pwd.is_empty() { None } else { Some(pwd) },
                            };
                        }
                        Err(zip_crypto::AesError::WrongPassword) => {
                            cleanup(out_dir);
                            last_msg = "密码不正确（AES 校验未通过）".into();
                            continue;
                        }
                        Err(zip_crypto::AesError::Cancelled) => {
                            cleanup(out_dir);
                            return Attempt::Cancelled;
                        }
                        Err(zip_crypto::AesError::Structure(msg)) => {
                            // 结构没吃透：回落 7z，让它再试一次
                            cleanup(out_dir);
                            on_event(Event::Phase {
                                task_id,
                                message: format!("AES 结构未完全识别，回落 7z（{msg}）"),
                            });
                        }
                        Err(e) => {
                            cleanup(out_dir);
                            last_msg = format!("AES 解压失败：{e}");
                            continue;
                        }
                    }
                } else {
                    // 校验值不对就是权威结论，不必再起 7z
                    cleanup(out_dir);
                    last_msg = "密码不正确（AES 校验未通过）".into();
                    continue;
                }
            }

            if !pwd.is_empty() && total > 0 {
                on_event(Event::Phase {
                    task_id,
                    message: format!(
                        "正在试候选密码 {}/{}：{}",
                        index.saturating_sub(1),
                        total,
                        mask_password(&pwd)
                    ),
                });
            }

            match self.sz.extract(archive, out_dir, &pwd, Some(&progress), None) {
                Ok((code, text)) => {
                    let (ok, wrong_pw, msg) = probe::classify_extract(code, &text);
                    if ok {
                        self.record_hit(&pwd, &source);
                        return Attempt::Success {
                            password: if pwd.is_empty() { None } else { Some(pwd) },
                        };
                    }
                    if wrong_pw {
                        cleanup(out_dir);
                        last_msg = msg;
                        continue;
                    }
                    cleanup(out_dir);
                    return Attempt::Failed { msg };
                }
                Err(Error::Cancelled) => {
                    cleanup(out_dir);
                    return Attempt::Cancelled;
                }
                Err(e) => {
                    cleanup(out_dir);
                    return Attempt::Failed {
                        msg: e.to_string(),
                    };
                }
            }
        }

        if skipped_by_filter > 0 && last_msg.is_empty() {
            last_msg = format!("{skipped_by_filter} 个候选被快速预筛排除");
        }
        Attempt::NeedsPassword { last_msg }
    }

    fn record_hit(&self, password: &str, source: &str) {
        if password.is_empty() {
            return;
        }
        if let Some(v) = &self.vault {
            let _ = v.record_success(password, source);
        }
    }

    fn collect(&self, inputs: &[PathBuf]) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for input in inputs {
            if input.is_dir() {
                for f in crate::walk::iter_files(input) {
                    // 分卷的非首卷没有完整 magic（7z 只在首卷写头），靠扩展名先收进来，
                    // 交给 collapse_volumes 决定「只解首卷」还是「缺首卷告警」。
                    if detect::looks_like_archive(&f) || detect::volume_info(&f).is_some() {
                        out.push(f);
                    }
                }
            } else if input.is_file() {
                out.push(input.clone());
            }
        }
        out
    }

    /// 把分卷序列收敛成「只解首卷」，缺首卷的整组跳过并给出明确告警。
    ///
    /// 为什么必须做：`a.part1.rar` 与 `a.part2.rar` 后缀都是 `.rar`，扩展名
    /// 判定会让它们各成一个任务，而非首卷单独解必然失败——用户会看到一条
    /// 无法理解的 FAILED，还白跑一轮探测。缺首卷时也不能硬解：直接说清少了
    /// 什么，比塞一个注定失败的任务有用。
    fn collapse_volumes<F: Fn(Event)>(
        &self,
        files: Vec<PathBuf>,
        on_event: &F,
        report: &mut RunReport,
    ) -> Vec<PathBuf> {
        use std::collections::{HashMap, HashSet};

        let mut groups: HashMap<(PathBuf, String), Vec<(u32, PathBuf)>> = HashMap::new();
        for f in &files {
            if let Some((base, index)) = detect::volume_info(f) {
                let parent = f.parent().unwrap_or(Path::new("")).to_path_buf();
                groups
                    .entry((parent, base))
                    .or_default()
                    .push((index, f.clone()));
            }
        }
        if groups.is_empty() {
            return files;
        }

        let mut skip: HashSet<PathBuf> = HashSet::new();
        for ((parent, base), mut members) in groups {
            members.sort_by_key(|m| m.0);
            let first_index = members[0].0;
            if first_index != 1 {
                let msg = format!(
                    "检测到分卷但缺少首卷，已跳过：{}（现有最小分卷序号 {}，请补齐序号 1 的首卷）",
                    parent.join(&base).display(),
                    first_index
                );
                report.warnings.push(msg.clone());
                on_event(Event::Warning {
                    task_id: None,
                    message: msg,
                });
                for (_, p) in members {
                    skip.insert(p);
                }
            } else {
                // 只留首卷，其余卷由 7z 自行按同目录顺序读取
                for (_, p) in members.into_iter().skip(1) {
                    skip.insert(p);
                }
            }
        }
        files.into_iter().filter(|f| !skip.contains(f)).collect()
    }

    /// 内层分卷归并：BFS 解开外层后，把同组内层分卷放到首卷旁边供 7z 读取。
    ///
    /// 典型场景：外层包把 `a.7z.001/.002` 解到了不同子目录，或者逐卷交付到了
    /// 不同位置——7z 只认「首卷同目录下连续命名」的整组，缺卷就报错。
    /// 这里用硬链接（不行再复制），解完立刻删掉链接，不动用户文件本体。
    fn join_sibling_volumes(&self, task: &Task, tasks: &[Task]) -> Vec<PathBuf> {
        use std::collections::HashMap;

        if task.parent_id.is_none() {
            return Vec::new();
        }
        let Some((base, index)) = detect::volume_info(&task.archive) else {
            return Vec::new();
        };
        if index != 1 {
            return Vec::new();
        }

        // 每个任务所属的「源目录」：沿父链爬到顶层输入所在的目录。
        // 任务按 BFS 顺序入表，父任务一定先于子任务出现，所以一趟就能算完。
        let mut roots: HashMap<u64, PathBuf> = HashMap::new();
        for t in tasks {
            let root = match t.parent_id.and_then(|pid| roots.get(&pid)) {
                Some(parent_root) => parent_root.clone(),
                None => t
                    .archive
                    .parent()
                    .unwrap_or(Path::new(""))
                    .to_path_buf(),
            };
            roots.insert(t.id, root);
        }
        let source_root = match task.parent_id.and_then(|pid| roots.get(&pid)) {
            Some(parent_root) => parent_root.clone(),
            None => task
                .archive
                .parent()
                .unwrap_or(Path::new(""))
                .to_path_buf(),
        };

        // 收集同层、同源目录、已完成的兄弟任务产物里的同组分卷
        let mut candidates: HashMap<u32, Vec<PathBuf>> = HashMap::new();
        for other in tasks {
            if other.id == task.id
                || other.status != TaskStatus::Done
                || other.depth + 1 != task.depth
            {
                continue;
            }
            if roots.get(&other.id) != Some(&source_root) {
                continue;
            }
            let Some(out_dir) = &other.out_dir else { continue };
            for member in crate::walk::iter_files(out_dir) {
                if let Some((member_base, member_index)) = detect::volume_info(&member) {
                    if member_base == base && member_index != 1 {
                        candidates.entry(member_index).or_default().push(member);
                    }
                }
            }
        }

        let mut created = Vec::new();
        for (vol_index, paths) in candidates {
            if paths.len() != 1 {
                continue; // 同名组有歧义时不混用
            }
            let source = &paths[0];
            let target = task.archive.parent().unwrap_or(Path::new("")).join(
                source.file_name().unwrap_or_default(),
            );
            if source == &target || target.exists() {
                continue;
            }
            let linked = std::fs::hard_link(source, &target).is_ok();
            if !linked {
                if std::fs::copy(source, &target).is_err() {
                    continue;
                }
            }
            let _ = vol_index;
            created.push(target);
        }
        created
    }

    fn find_nested(&self, out_dir: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        for path in crate::walk::iter_files(out_dir) {
            let ext = path
                .extension()
                .map(|e| format!(".{}", e.to_string_lossy().to_ascii_lowercase()))
                .unwrap_or_default();
            if COMPOUND_ZIP_EXTS.contains(&ext.as_str()) {
                continue;
            }
            if VIDEO_EXTS.contains(&ext.as_str()) && detect::find_embedded_zip(&path).is_none() {
                continue;
            }
            if probe::is_non_first_volume(&path) {
                continue;
            }
            if detect::looks_like_archive(&path) {
                found.push(path);
            }
        }
        found
    }
}

fn cleanup(dir: &Path) {
    // 只清空本次尝试写出的目录：这是产物暂存区，不是用户原目录
    let _ = std::fs::remove_dir_all(dir);
}

fn mask_password(pwd: &str) -> String {
    let chars: Vec<char> = pwd.chars().collect();
    if chars.len() <= 2 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..2].iter().collect();
    format!("{head}{}", "*".repeat(chars.len() - 2))
}

/// 同卷 rename，跨卷复制后删除源
fn deliver(src: &Path, dst: &Path) {
    if let Some(parent) = dst.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if output::same_volume(src, dst) {
        if std::fs::rename(src, dst).is_ok() {
            if let Some(parent) = src.parent() {
                let _ = std::fs::remove_dir_all(parent);
            }
            return;
        }
    }
    // 复制失败只记警告，不影响任务成功（警告汇总在后续阶段接入）
    if copy_tree(src, dst).is_ok() {
        let _ = std::fs::remove_dir_all(src);
    }
}

fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_tree(&from, &to)?;
        } else if from.is_file() {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}
