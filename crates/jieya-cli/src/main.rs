use std::path::PathBuf;
use std::process::ExitCode;

use jieya_core::detect::collect_inputs;
use jieya_core::fmt::human_size;
use jieya_core::models::TaskStatus;
use jieya_core::output::OutputMode;
use jieya_core::{Config, Event, Pipeline};

const USAGE: &str = r#"解压开镜（Rust 版）

用法:
  jieya extract <路径...> [选项]     递归解压压缩包/目录
  jieya detect <路径...>              只看类型，不解压
  jieya encoding <压缩包>             看包内文件名的编码判定
  jieya cleanup [scan|prune] [选项]   暂存区残留盘点/清理
  jieya tasks [--db <path>]           任务历史
  jieya vault [list|add|rm|stats]     密码库
  jieya vault export [备份.vault]      加密导出密码库（口令走 --password 或环境变量）
  jieya vault import <备份.vault>      解密合并到本地库
  jieya version                       显示版本与 7z

选项:
  --sevenzip <path>   指定 7z.exe
  --workdir <dir>     隔离工作目录
  --vault <path>      指定密码库路径
  --mode samedir      解到压缩包旁边（默认）
  --mode workdir      解到隔离目录，成功后再交付回源目录
  --out <dir>         解到指定目录（顶层产物落在 <dir>/<包名>/）
  --password <pwd>    手动指定一个候选密码
  --max-depth <n>     递归深度上限（默认 5）
  --quiet             只输出结果
  --workdir <dir>     cleanup 的盘点根（默认配置的工作目录）
  --db <path>         tasks 用的任务库（默认与密码库同一个 jieya.db）
  --all               cleanup prune 时连「请保留/待确认」也删（危险）
"#;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        println!("{USAGE}");
        return ExitCode::FAILURE;
    }
    let cmd = args[0].clone();
    let rest = &args[1..];

    match cmd.as_str() {
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        "version" | "-V" | "--version" => {
            println!("jieya {}", env!("CARGO_PKG_VERSION"));
            match Config::create(None, None) {
                Ok(cfg) => {
                    let sz = jieya_core::SevenZip::new(cfg.sevenzip_path.clone(), 30, 60);
                    match sz.version() {
                        Ok(v) => println!("{}", v),
                        Err(e) => println!("7z: {e}"),
                    }
                }
                Err(e) => println!("7z: {e}"),
            }
            ExitCode::SUCCESS
        }
        "detect" => run_detect(rest),
        "encoding" | "enc" => run_encoding(rest),
        "cleanup" | "clean" => run_cleanup(rest),
        "tasks" => run_tasks(rest),
        "extract" | "x" => run_extract(rest),
        "vault" => run_vault(rest),
        other => {
            eprintln!("未知命令: {other}\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn run_detect(args: &[String]) -> ExitCode {
    let cfg = match Config::create(None, None) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let sz = jieya_core::SevenZip::new(cfg.sevenzip_path.clone(), 120, 60);
    let mut any = false;
    for input in collect_inputs(&args.iter().map(PathBuf::from).collect::<Vec<_>>()) {
        any = true;
        match jieya_core::probe::probe(&sz, &input) {
            Ok(info) => {
                let flag = if info.flag_encrypted { " [加密]" } else { "" };
                println!(
                    "{}  format={}  size={}  解压后={}  文件={}  目录={}{}{}",
                    input.display(),
                    if info.format_name.is_empty() {
                        "?".to_string()
                    } else {
                        info.format_name.clone()
                    },
                    human_size(info.archive_size),
                    human_size(info.total_uncompressed),
                    info.file_count,
                    info.dir_count,
                    if info.volume_count > 1 {
                        format!("  分卷={}", info.volume_count)
                    } else {
                        String::new()
                    },
                    flag
                );
            }
            Err(e) => println!("{}  探测失败: {e}", input.display()),
        }
    }
    if !any {
        eprintln!("没有找到压缩包");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run_encoding(args: &[String]) -> ExitCode {
    let paths: Vec<PathBuf> = args.iter().map(PathBuf::from).collect();
    if paths.is_empty() {
        eprintln!("用法: jieya encoding <压缩包>");
        return ExitCode::FAILURE;
    }
    for path in paths {
        println!("{}", path.display());
        match jieya_core::name_repair::detect_name_encoding(&path, 4000) {
            Some(v) => {
                println!("  判定: {}", v.describe());
                for (label, score) in &v.scores {
                    println!("    {label:<10} {score:.4}");
                }
            }
            None => println!("  判不了（不是 zip／没有条目名／打不开）"),
        }
    }
    ExitCode::SUCCESS
}

fn run_cleanup(args: &[String]) -> ExitCode {
    let mut action = "scan".to_string();
    let mut workdir: Option<PathBuf> = None;
    let mut db: Option<PathBuf> = None;
    let mut allow_unsafe = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "scan" | "prune" => {
                action = args[i].clone();
                i += 1;
            }
            "--workdir" => {
                i += 1;
                workdir = args.get(i).map(PathBuf::from);
                i += 1;
            }
            "--db" => {
                i += 1;
                db = args.get(i).map(PathBuf::from);
                i += 1;
            }
            "--all" => {
                allow_unsafe = true;
                i += 1;
            }
            other => {
                eprintln!("未知参数: {other}");
                return ExitCode::FAILURE;
            }
        }
    }
    let cfg = match Config::create(None, workdir.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let db_path = match db {
        Some(p) => p,
        None => cfg.vault_path.clone(),
    };
    let store = jieya_core::TaskStore::open(&db_path).ok();
    let leftovers = jieya_core::cleanup::scan(&cfg.workdir, store.as_ref(), 500_000);
    if leftovers.is_empty() {
        println!("{} 里没有残留", cfg.workdir.display());
        return ExitCode::SUCCESS;
    }
    let mut total = 0u64;
    for lo in &leftovers {
        total += lo.size;
        println!(
            "{:<8} {:>10}  {:>7} 项  {}  [{}]",
            lo.kind.label(),
            human_size(lo.size),
            lo.files,
            lo.path.display(),
            lo.reason
        );
    }
    println!(
        "合计 {} 项，{}",
        leftovers.len(),
        human_size(total)
    );

    if action == "prune" {
        let (freed, errors) = jieya_core::cleanup::prune(&leftovers, &cfg.workdir, allow_unsafe);
        println!("已释放 {}", human_size(freed));
        for e in &errors {
            eprintln!("{e}");
        }
    } else {
        println!("用 `jieya cleanup prune` 清理「可清理」项（加 --all 连保留项一起删）");
    }
    ExitCode::SUCCESS
}

fn run_tasks(args: &[String]) -> ExitCode {
    let mut db: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--db" {
            i += 1;
            db = args.get(i).map(PathBuf::from);
        }
        i += 1;
    }
    let path = match db {
        Some(p) => p,
        None => match Config::create(None, None) {
            Ok(c) => c.vault_path,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        },
    };
    match jieya_core::TaskStore::open(&path) {
        Ok(store) => match store.list_all() {
            Ok(tasks) => {
                println!("任务库: {}（{} 条）", path.display(), tasks.len());
                for t in tasks {
                    println!(
                        "#{:<5} {:<14} 深度{}  {}  {}",
                        t.id,
                        t.status.as_str(),
                        t.depth,
                        t.archive_path,
                        if t.extracted_dir.is_empty() {
                            String::new()
                        } else {
                            format!("→ {}", t.extracted_dir)
                        }
                    );
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run_vault(args: &[String]) -> ExitCode {
    let mut db: Option<PathBuf> = None;
    let mut action: Vec<String> = Vec::new();
    let mut password: Option<String> = None;
    let mut n_log2: Option<u8> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--vault" => {
                i += 1;
                db = args.get(i).map(PathBuf::from);
            }
            "--password" | "-p" => {
                i += 1;
                password = args.get(i).cloned();
            }
            "--n" => {
                i += 1;
                n_log2 = args.get(i).and_then(|v| v.parse::<u8>().ok());
            }
            other => action.push(other.to_string()),
        }
        i += 1;
    }

    let path = db.unwrap_or_else(jieya_core::Vault::default_path);
    if action.first().map(|s| s.as_str()) == Some("path") {
        println!("{}", path.display());
        return ExitCode::SUCCESS;
    }
    let vault = match jieya_core::Vault::open(&path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let sub = action.first().map(|s| s.as_str()).unwrap_or("list");
    match sub {
        "stats" => match vault.sources() {
            Ok(sources) => {
                println!("密码库: {}（{} 条）", path.display(), vault.count().unwrap_or(0));
                for s in sources {
                    let name = if s.source.is_empty() { "(无来源)" } else { &s.source };
                    println!("  {:<24} {:>5} 条  命中 {}", name, s.count, s.total_hits);
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
        "add" => {
            let Some(pwd) = action.get(1) else {
                eprintln!("用法: jieya vault add <密码> [来源]");
                return ExitCode::FAILURE;
            };
            let source = action.get(2).map(|s| s.as_str()).unwrap_or("");
            match vault.add_manual(pwd, source) {
                Ok(()) => {
                    println!("已录入（{}）", path.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::FAILURE
                }
            }
        }
        "rm" => {
            let Some(id) = action.get(1).and_then(|v| v.parse::<i64>().ok()) else {
                eprintln!("用法: jieya vault rm <id>");
                return ExitCode::FAILURE;
            };
            match vault.delete(id) {
                Ok(true) => {
                    println!("已删除 #{id}");
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("没有 #{id}");
                    ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::FAILURE
                }
            }
        }
        "export" => {
            let dest = action
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| jieya_core::vault_io::default_export_path(&std::env::current_dir().unwrap_or_default()));
            let Some(pwd) = resolve_vault_password(password) else {
                return ExitCode::FAILURE;
            };
            let n = n_log2.unwrap_or(jieya_core::bundle::DEFAULT_N_LOG2);
            match jieya_core::export_vault(&vault, &dest, &pwd, n) {
                Ok(r) => {
                    println!(
                        "已导出 {} 条密码 -> {}（明文 {}，密文 {}）",
                        r.entries,
                        r.path.display(),
                        human_size(r.plaintext_bytes as u64),
                        human_size(r.bundle_bytes as u64)
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("导出失败: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "import" => {
            let Some(src) = action.get(1).map(PathBuf::from) else {
                eprintln!("用法: jieya vault import <备份.vault> [--password 口令]");
                return ExitCode::FAILURE;
            };
            let Some(pwd) = resolve_vault_password(password) else {
                return ExitCode::FAILURE;
            };
            match jieya_core::import_vault(&vault, &src, &pwd) {
                Ok(r) => {
                    println!(
                        "已合并 {}：共 {} 条，新增 {} 条，更新 {} 条{}",
                        r.path.display(),
                        r.total,
                        r.added,
                        r.merged,
                        r.exported_at
                            .as_ref()
                            .map(|s| format!("（导出于 {s}）"))
                            .unwrap_or_default()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("导入失败: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => match vault.query("", None, "source", false, 0) {
            Ok(entries) => {
                println!("密码库: {}（{} 条）", path.display(), entries.len());
                for e in entries {
                    let src = if e.source.is_empty() { "-" } else { &e.source };
                    println!(
                        "#{:<5} {:<24} {:<20} 命中 {}",
                        e.id, src, e.password, e.hit_count
                    );
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
    }
}

fn resolve_vault_password(from_args: Option<String>) -> Option<String> {
    if let Some(p) = from_args.filter(|p| !p.is_empty()) {
        return Some(p);
    }
    if let Ok(p) = std::env::var("JIEYA_VAULT_PASSWORD") {
        if !p.is_empty() {
            return Some(p);
        }
    }
    eprint!("口令（直接回车取消）: ");
    use std::io::Write;
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return None;
    }
    let pwd = line.trim_end_matches(['\r', '\n']).to_string();
    if pwd.is_empty() {
        eprintln!("已取消：口令不能为空");
        None
    } else {
        Some(pwd)
    }
}

fn run_extract(args: &[String]) -> ExitCode {
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut sevenzip: Option<String> = None;
    let mut workdir: Option<PathBuf> = None;
    let mut vault_path: Option<PathBuf> = None;
    let mut mode = OutputMode::SameDir;
    let mut max_depth: Option<u32> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut password: Option<String> = None;
    let mut quiet = false;

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--sevenzip" => {
                i += 1;
                sevenzip = args.get(i).cloned();
            }
            "--workdir" => {
                i += 1;
                workdir = args.get(i).map(PathBuf::from);
            }
            "--vault" => {
                i += 1;
                vault_path = args.get(i).map(PathBuf::from);
            }
            "--mode" => {
                i += 1;
                match args.get(i).map(|s| s.as_str()) {
                    Some("samedir") => mode = OutputMode::SameDir,
                    Some("workdir") => mode = OutputMode::Workdir,
                    other => {
                        eprintln!("--mode 只支持 samedir / workdir，收到 {:?}", other);
                        return ExitCode::FAILURE;
                    }
                }
            }
            "--max-depth" => {
                i += 1;
                max_depth = args.get(i).and_then(|v| v.parse().ok());
            }
            "--out" => {
                i += 1;
                out_dir = args.get(i).map(PathBuf::from);
            }
            "--password" => {
                i += 1;
                password = args.get(i).cloned();
            }
            "--quiet" => quiet = true,
            _ if a.starts_with('-') => {
                eprintln!("未知选项: {a}");
                return ExitCode::FAILURE;
            }
            _ => paths.push(PathBuf::from(a)),
        }
        i += 1;
    }

    if paths.is_empty() {
        eprintln!("请给出要解压的路径\n\n{USAGE}");
        return ExitCode::FAILURE;
    }

    let mut cfg = match Config::create(sevenzip.as_deref(), workdir.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(d) = max_depth {
        cfg.max_depth = d;
    }
    if let Some(v) = vault_path {
        cfg.vault_path = v;
    }

    let mut pipeline = Pipeline::new(cfg);
    pipeline.set_destination(out_dir);
    pipeline.set_password(password);
    let on_event = |ev: Event| {
        if quiet {
            return;
        }
        match ev {
            Event::TaskStarted {
                task_id,
                archive,
                depth,
            } => {
                eprintln!(
                    "[{task_id}] {} (第 {} 层)",
                    archive.display(),
                    depth + 1
                )
            }
            Event::TaskInfo {
                task_id: _,
                format,
                archive_size,
                total_uncompressed,
                file_count,
                encrypted,
                volumes,
            } => {
                let mut line = format!(
                    "      {} · {} · 解压后 {} · {} 个文件",
                    if format.is_empty() { "?" } else { &format },
                    human_size(archive_size),
                    human_size(total_uncompressed),
                    file_count
                );
                if volumes > 1 {
                    line.push_str(&format!(" · {} 个分卷", volumes));
                }
                if encrypted {
                    line.push_str(" · 加密");
                }
                eprintln!("{line}");
            }
            Event::Progress { task_id, percent } => {
                eprint!("\r[{task_id}] 解压 {percent:>3}%");
                if percent >= 100 {
                    eprintln!();
                }
            }
            Event::TaskDone {
                task_id,
                out_dir,
                ..
            } => eprintln!("[{task_id}] 完成 → {}", out_dir.display()),
            Event::TaskFailed {
                task_id, reason, ..
            } => eprintln!("[{task_id}] 失败: {reason}"),
            Event::TaskSkipped {
                task_id,
                reason,
                ..
            } => eprintln!("[{task_id}] 跳过: {reason}"),
            Event::Phase { task_id, message } => eprintln!("[{task_id}] {message}"),
            Event::NameRepaired {
                task_id,
                count,
                encoding,
                sample,
            } => {
                let mut line = format!("[{task_id}] 已修正 {count} 个乱码文件名");
                if !encoding.is_empty() {
                    line.push_str(&format!("（{encoding}）"));
                }
                if let Some((old, new)) = sample {
                    line.push_str(&format!("，例如 {old} → {new}"));
                }
                eprintln!("{line}");
            }
            Event::NestedFound { task_id, archive } => {
                eprintln!("[{task_id}] 发现内层包 {}", archive.display())
            }
            Event::Warning { task_id, message } => match task_id {
                Some(id) => eprintln!("[{id}] 警告: {message}"),
                None => eprintln!("警告: {message}"),
            },
        }
    };

    match pipeline.run(&paths, mode, &on_event) {
        Ok(report) => {
            println!(
                "\n完成：解压 {} 个，失败 {} 个，待密码 {} 个，跳过 {} 个",
                report.extracted, report.failed, report.needs_password, report.skipped
            );
            let bad: Vec<_> = report
                .tasks
                .iter()
                .filter(|t| t.status == TaskStatus::Failed)
                .collect();
            for t in bad {
                println!(
                    "  失败: {} — {}",
                    t.archive.display(),
                    t.error.as_deref().unwrap_or("")
                );
            }
            if report.failed > 0 {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("执行失败: {e}");
            ExitCode::FAILURE
        }
    }
}
