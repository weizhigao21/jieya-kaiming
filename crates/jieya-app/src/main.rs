//! Tauri v2 外壳：窗口 + IPC 命令，引擎全部来自 jieya-core。
//!
//! 体积取向：前端是纯静态 HTML/CSS/JS（不引 npm 工程），界面依赖系统 WebView2。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use jieya_core::{cleanup, name_repair, Config, Event, Pipeline, SevenZip, TaskStore, Vault};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::ipc::Channel;
use tauri::{Manager, State};

struct AppState {
    cfg: Mutex<Config>,
    running: Arc<AtomicBool>,
    config_path: PathBuf,
    /// 启动时从命令行带进来的路径（右键菜单会传 "%1"）
    initial_paths: Vec<String>,
    /// 右键「解压到指定目录」启动：先弹目录选择框
    pick_dir_on_start: bool,
    /// 右键带路径启动：走小窗进度模式，完成后自动关
    quick_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Settings {
    sevenzip: String,
    workdir: String,
    max_depth: u32,
    max_password_attempts: usize,
    delete_intermediate: bool,
    overwrite_existing: bool,
    skip_done: bool,
}

impl Settings {
    fn from_config(cfg: &Config) -> Self {
        Self {
            sevenzip: cfg.sevenzip_path.to_string_lossy().to_string(),
            workdir: cfg.workdir.to_string_lossy().to_string(),
            max_depth: cfg.max_depth,
            max_password_attempts: cfg.max_password_attempts,
            delete_intermediate: cfg.delete_intermediate,
            overwrite_existing: cfg.overwrite_existing,
            skip_done: cfg.skip_done,
        }
    }

    fn apply(&self, cfg: &mut Config) -> Result<(), String> {
        let sevenzip = if self.sevenzip.trim().is_empty() {
            None
        } else {
            Some(self.sevenzip.trim())
        };
        let workdir = if self.workdir.trim().is_empty() {
            None
        } else {
            Some(PathBuf::from(self.workdir.trim()))
        };
        let fresh = Config::create(sevenzip, workdir.as_deref()).map_err(|e| e.to_string())?;
        cfg.sevenzip_path = fresh.sevenzip_path;
        cfg.workdir = fresh.workdir;
        cfg.max_depth = self.max_depth.max(1);
        cfg.max_password_attempts = self.max_password_attempts.max(1);
        cfg.delete_intermediate = self.delete_intermediate;
        cfg.overwrite_existing = self.overwrite_existing;
        cfg.skip_done = self.skip_done;
        Ok(())
    }
}

fn config_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    base.join("解压开镜").join("config.json")
}

fn load_settings() -> (Config, Settings) {
    let mut cfg = Config::create(None, None).unwrap_or_else(|_| {
        // 7z 找不到也要让界面能开：给一个占位路径，用户可在设置里改
        let mut c = Config {
            sevenzip_path: PathBuf::from(r"C:\APP\7Z\7-Zip\7z.exe"),
            workdir: std::env::temp_dir().join("jieya_workspace"),
            vault_path: Vault::default_path(),
            max_depth: 5,
            max_total_uncompressed: 50 * 1024 * 1024 * 1024,
            max_compression_ratio: 1000.0,
            ratio_floor_bytes: 1024 * 1024 * 1024,
            max_password_attempts: 20,
            delete_intermediate: true,
            keep_original: true,
            sniff_archives: true,
            overwrite_existing: false,
            skip_done: true,
            list_timeout_secs: 120,
            extract_timeout_secs: 3600,
            cloud_unlock: false,
            cloud_unlock_timeout_secs: 10,
            cloud_unlock_udid: String::new(),
        };
        c.workdir = std::env::temp_dir().join("jieya_workspace");
        c
    });
    let path = config_path();
    let mut settings = Settings::from_config(&cfg);
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(saved) = serde_json::from_str::<Settings>(&text) {
            if saved.apply(&mut cfg).is_ok() {
                settings = saved;
            }
        }
    }
    (cfg, settings)
}

fn event_json(ev: &Event) -> Value {
    match ev {
        Event::TaskStarted {
            task_id,
            archive,
            depth,
        } => json!({
            "kind": "started", "taskId": task_id,
            "archive": archive.to_string_lossy(), "depth": depth
        }),
        Event::TaskInfo {
            task_id,
            format,
            archive_size,
            total_uncompressed,
            file_count,
            encrypted,
            volumes,
        } => json!({
            "kind": "info", "taskId": task_id, "format": format,
            "archiveSize": archive_size, "total": total_uncompressed,
            "files": file_count, "encrypted": encrypted, "volumes": volumes
        }),
        Event::Phase { task_id, message } => {
            json!({ "kind": "phase", "taskId": task_id, "message": message })
        }
        Event::Progress { task_id, percent } => {
            json!({ "kind": "progress", "taskId": task_id, "percent": percent })
        }
        Event::TaskDone {
            task_id,
            archive,
            out_dir,
        } => json!({
            "kind": "done", "taskId": task_id,
            "archive": archive.to_string_lossy(), "outDir": out_dir.to_string_lossy()
        }),
        Event::TaskFailed {
            task_id,
            archive,
            reason,
        } => json!({
            "kind": "failed", "taskId": task_id,
            "archive": archive.to_string_lossy(), "reason": reason
        }),
        Event::TaskSkipped {
            task_id,
            archive,
            reason,
        } => json!({
            "kind": "skipped", "taskId": task_id,
            "archive": archive.to_string_lossy(), "reason": reason
        }),
        Event::NestedFound { task_id, archive } => json!({
            "kind": "nested", "taskId": task_id, "archive": archive.to_string_lossy()
        }),
        Event::NameRepaired {
            task_id,
            count,
            encoding,
            sample,
        } => json!({
            "kind": "renamed", "taskId": task_id, "count": count,
            "encoding": encoding,
            "sample": sample.as_ref().map(|(a, b)| json!([a, b]))
        }),
        Event::Warning { task_id, message } => json!({
            "kind": "warning", "taskId": task_id, "message": message
        }),
    }
}

// ---------------------------------------------------------------------------
// 命令
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_settings(state: State<'_, AppState>) -> Result<Value, String> {
    let cfg = state.cfg.lock().map_err(|e| e.to_string())?;
    let settings = Settings::from_config(&cfg);
    let sz = SevenZip::new(cfg.sevenzip_path.clone(), 30, 60);
    Ok(json!({
        "settings": settings,
        "sevenzipVersion": sz.version().unwrap_or_else(|e| e.to_string()),
        "sevenzipOk": cfg.sevenzip_path.is_file(),
        "vaultPath": cfg.vault_path.to_string_lossy(),
        "dataDir": config_path().parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[tauri::command]
fn save_settings(state: State<'_, AppState>, settings: Settings) -> Result<Value, String> {
    {
        let mut cfg = state.cfg.lock().map_err(|e| e.to_string())?;
        settings.apply(&mut cfg)?;
    }
    std::fs::write(
        &state.config_path,
        serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("保存设置失败: {e}"))?;
    get_settings(state)
}

#[tauri::command]
fn pick_inputs(folder: bool) -> Vec<String> {
    let dialog = rfd::FileDialog::new().add_filter(
        "压缩包",
        &["zip", "rar", "7z", "cbz", "cbr", "tar", "gz", "bz2", "xz", "cab", "iso", "001"],
    );
    if folder {
        dialog
            .pick_folder()
            .map(|p| vec![p.to_string_lossy().to_string()])
            .unwrap_or_default()
    } else {
        dialog
            .pick_files()
            .map(|ps| {
                ps.into_iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[tauri::command]
fn pick_folder() -> Option<String> {
    rfd::FileDialog::new()
        .pick_folder()
        .map(|p| p.to_string_lossy().to_string())
}

#[tauri::command]
fn pick_save(default_name: String) -> Option<String> {
    rfd::FileDialog::new()
        .add_filter("密码库备份", &["vault"])
        .set_file_name(&default_name)
        .save_file()
        .map(|p| p.to_string_lossy().to_string())
}

#[tauri::command]
fn pick_backup() -> Option<String> {
    rfd::FileDialog::new()
        .add_filter("密码库备份", &["vault"])
        .pick_file()
        .map(|p| p.to_string_lossy().to_string())
}

#[tauri::command]
fn vault_export(state: State<'_, AppState>, dest: String, password: String) -> Result<Value, String> {
    let cfg = state.cfg.lock().map_err(|e| e.to_string())?.clone();
    let vault = Vault::open(&cfg.vault_path).map_err(|e| e.to_string())?;
    let r = jieya_core::export_vault(
        &vault,
        Path::new(&dest),
        &password,
        jieya_core::bundle::DEFAULT_N_LOG2,
    )
    .map_err(|e| e.to_string())?;
    Ok(json!({
        "path": r.path.to_string_lossy(), "entries": r.entries,
        "plaintextBytes": r.plaintext_bytes, "bundleBytes": r.bundle_bytes
    }))
}

#[tauri::command]
fn vault_import(state: State<'_, AppState>, src: String, password: String) -> Result<Value, String> {
    let cfg = state.cfg.lock().map_err(|e| e.to_string())?.clone();
    let vault = Vault::open(&cfg.vault_path).map_err(|e| e.to_string())?;
    let r = jieya_core::import_vault(&vault, Path::new(&src), &password)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "path": r.path.to_string_lossy(), "added": r.added, "merged": r.merged,
        "total": r.total, "exportedAt": r.exported_at
    }))
}

#[tauri::command]
fn start_extract(
    state: State<'_, AppState>,
    paths: Vec<String>,
    destination: Option<String>,
    password: Option<String>,
    on_event: Channel<Value>,
) -> Result<(), String> {
    if state.running.swap(true, Ordering::SeqCst) {
        return Err("已有任务正在运行，等它结束再试".into());
    }
    let cfg = state
        .cfg
        .lock()
        .map_err(|e| e.to_string())?
        .clone();
    let running = state.running.clone();

    std::thread::spawn(move || {
        let mut pipeline = Pipeline::new(cfg);
        pipeline.skip_done = pipeline.cfg.skip_done;
        pipeline.set_destination(destination.filter(|d| !d.trim().is_empty()).map(PathBuf::from));
        pipeline.set_password(password.filter(|p| !p.is_empty()));
        let progress_channel = on_event.clone();
        let on = |ev: Event| {
            let _ = progress_channel.send(event_json(&ev));
        };
        let input: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
        let started = std::time::Instant::now();
        let result = pipeline.run(&input, jieya_core::output::OutputMode::SameDir, &on);
        let payload = match result {
            Ok(report) => json!({
                "kind": "summary",
                "extracted": report.extracted,
                "failed": report.failed,
                "needsPassword": report.needs_password,
                "skipped": report.skipped,
                "elapsedMs": started.elapsed().as_millis() as u64,
            }),
            Err(e) => json!({ "kind": "summary", "error": e.to_string() }),
        };
        let _ = on_event.send(payload);
        running.store(false, Ordering::SeqCst);
    });
    Ok(())
}

#[tauri::command]
fn detect_paths(state: State<'_, AppState>, paths: Vec<String>) -> Result<Vec<Value>, String> {
    let cfg = state.cfg.lock().map_err(|e| e.to_string())?.clone();
    let sz = SevenZip::new(cfg.sevenzip_path.clone(), 120, 60);
    let inputs: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
    let mut out = Vec::new();
    for input in jieya_core::detect::collect_inputs(&inputs) {
        match jieya_core::probe::probe(&sz, &input) {
            Ok(info) => out.push(json!({
                "path": input.to_string_lossy(),
                "format": info.format_name,
                "archiveSize": info.archive_size,
                "total": info.total_uncompressed,
                "files": info.file_count,
                "dirs": info.dir_count,
                "encrypted": info.flag_encrypted || info.needs_password_for_listing,
                "volumes": info.volume_count,
            })),
            Err(e) => out.push(json!({
                "path": input.to_string_lossy(), "error": e.to_string()
            })),
        }
    }
    Ok(out)
}

#[tauri::command]
fn vault_list(
    state: State<'_, AppState>,
    keyword: String,
    limit: usize,
) -> Result<Vec<Value>, String> {
    let cfg = state.cfg.lock().map_err(|e| e.to_string())?.clone();
    let vault = Vault::open(&cfg.vault_path).map_err(|e| e.to_string())?;
    let entries = vault
        .query(&keyword, None, "source", false, limit.max(1))
        .map_err(|e| e.to_string())?;
    Ok(entries
        .into_iter()
        .map(|e| {
            json!({
                "id": e.id, "password": e.password, "source": e.source,
                "hitCount": e.hit_count, "createdAt": e.created_at, "lastHitAt": e.last_hit_at
            })
        })
        .collect())
}

#[tauri::command]
fn vault_add(state: State<'_, AppState>, password: String, source: String) -> Result<(), String> {
    let cfg = state.cfg.lock().map_err(|e| e.to_string())?.clone();
    let vault = Vault::open(&cfg.vault_path).map_err(|e| e.to_string())?;
    vault
        .add_manual(&password, source.trim())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn vault_delete(state: State<'_, AppState>, id: i64) -> Result<bool, String> {
    let cfg = state.cfg.lock().map_err(|e| e.to_string())?.clone();
    let vault = Vault::open(&cfg.vault_path).map_err(|e| e.to_string())?;
    vault.delete(id).map_err(|e| e.to_string())
}

#[tauri::command]
fn vault_stats(state: State<'_, AppState>) -> Result<Value, String> {
    let cfg = state.cfg.lock().map_err(|e| e.to_string())?.clone();
    let vault = Vault::open(&cfg.vault_path).map_err(|e| e.to_string())?;
    let count = vault.count().map_err(|e| e.to_string())?;
    let sources = vault.sources().map_err(|e| e.to_string())?;
    Ok(json!({
        "count": count,
        "sources": sources.into_iter().map(|s| json!({
            "source": s.source, "count": s.count
        })).collect::<Vec<_>>()
    }))
}

#[tauri::command]
fn cleanup_scan(state: State<'_, AppState>) -> Result<Value, String> {
    let cfg = state.cfg.lock().map_err(|e| e.to_string())?.clone();
    let store = TaskStore::open(&cfg.vault_path).ok();
    let leftovers = cleanup::scan(&cfg.workdir, store.as_ref(), 500_000);
    let total: u64 = leftovers.iter().map(|l| l.size).sum();
    Ok(json!({
        "workdir": cfg.workdir.to_string_lossy(),
        "totalBytes": total,
        "items": leftovers.iter().map(|l| json!({
            "path": l.path.to_string_lossy(),
            "taskId": l.task_id,
            "kind": l.kind.label(),
            "safe": l.safe(),
            "reason": l.reason,
            "size": l.size,
            "files": l.files,
        })).collect::<Vec<_>>()
    }))
}

#[tauri::command]
fn cleanup_prune(state: State<'_, AppState>, allowUnsafe: bool, paths: Vec<String>) -> Result<Value, String> {
    let cfg = state.cfg.lock().map_err(|e| e.to_string())?.clone();
    let store = TaskStore::open(&cfg.vault_path).ok();
    let mut leftovers = cleanup::scan(&cfg.workdir, store.as_ref(), 500_000);
    if !paths.is_empty() {
        leftovers.retain(|l| paths.iter().any(|p| Path::new(p) == l.path));
    }
    let (freed, errors) = cleanup::prune(&leftovers, &cfg.workdir, allowUnsafe);
    Ok(json!({ "freed": freed, "errors": errors }))
}

#[tauri::command]
fn encoding_detail(path: String) -> Result<Value, String> {
    let p = PathBuf::from(&path);
    Ok(match name_repair::detect_name_encoding(&p, 4000) {
        Some(v) => json!({
            "label": v.label, "names": v.names, "confident": v.confident,
            "margin": v.margin, "reason": v.reason, "describe": v.describe(),
            "scores": v.scores.iter().map(|(k, s)| json!([k, s])).collect::<Vec<_>>()
        }),
        None => json!({ "describe": "判不了（不是 zip／没有条目名／打不开）" }),
    })
}

#[tauri::command]
fn startup_paths(state: State<'_, AppState>) -> Vec<String> {
    state.initial_paths.clone()
}

#[tauri::command]
fn startup_pick_dir(state: State<'_, AppState>) -> bool {
    state.pick_dir_on_start
}

#[tauri::command]
fn startup_quick(state: State<'_, AppState>) -> bool {
    state.quick_mode
}

#[tauri::command]
fn win_minimize(window: tauri::WebviewWindow) -> Result<(), String> {
    window.minimize().map_err(|e| e.to_string())
}

#[tauri::command]
fn win_toggle_max(window: tauri::WebviewWindow) -> Result<(), String> {
    if window.is_maximized().unwrap_or(false) {
        window.unmaximize().map_err(|e| e.to_string())
    } else {
        window.maximize().map_err(|e| e.to_string())
    }
}

#[tauri::command]
fn win_is_max(window: tauri::WebviewWindow) -> bool {
    window.is_maximized().unwrap_or(false)
}

#[tauri::command]
fn show_window(window: tauri::WebviewWindow) -> Result<(), String> {
    // 窗口创建时是隐藏的，前端把主界面/小窗排好后再显示，避免启动时闪一下主 UI。
    window.show().map_err(|e| e.to_string())?;
    let _ = window.set_focus();
    Ok(())
}

#[tauri::command]
fn enter_quick(window: tauri::WebviewWindow) -> Result<(), String> {
    window
        .set_min_size(Some(tauri::LogicalSize::new(520.0, 280.0)))
        .map_err(|e| e.to_string())?;
    window
        .set_size(tauri::LogicalSize::new(600.0, 310.0))
        .map_err(|e| e.to_string())?;
    let _ = window.set_resizable(false);
    let _ = window.set_maximizable(false);
    let _ = window.center();
    Ok(())
}

#[tauri::command]
fn close_window(window: tauri::WebviewWindow) -> Result<(), String> {
    window.close().map_err(|e| e.to_string())
}

const MENU_KEY: &str = r"HKCU\Software\Classes\Directory\shell\JieyaKaiming";
const MENU_BG_KEY: &str = r"HKCU\Software\Classes\Directory\Background\shell\JieyaKaiming";
const MENU_FILE_KEY: &str = r"HKCU\Software\Classes\*\shell\JieyaKaiming";

fn reg(args: &[&str]) -> Result<(), String> {
    // 用 reg.exe 而不是引 winreg：只为一条菜单多带一个 crate 不划算
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let mut cmd = std::process::Command::new("reg.exe");
        cmd.args(args).creation_flags(0x0800_0000);
        let out = cmd.output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
    }
    Ok(())
}

fn exe_path() -> String {
    std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

#[tauri::command]
fn install_menu() -> Result<String, String> {
    let exe = exe_path();
    if exe.is_empty() {
        return Err("拿不到 exe 路径".into());
    }
    for key in [MENU_KEY, MENU_BG_KEY] {
        let _ = reg(&["delete", key, "/f"]);
    }
    for (key, arg) in [(MENU_FILE_KEY, "%1")] {
        // 旧的单条命令值要删掉，否则菜单不会展开成子菜单
        let _ = reg(&["delete", &format!("{key}\\command"), "/f"]);
        reg(&["add", key, "/v", "MUIVerb", "/d", "解压开镜", "/f"])?;
        reg(&["add", key, "/v", "SubCommands", "/d", "", "/f"])?;
        reg(&["add", key, "/v", "Icon", "/d", &exe, "/f"])?;

        let here = format!("{key}\\shell\\01here");
        reg(&["add", &here, "/ve", "/d", "解压到当前目录", "/f"])?;
        reg(&["add", &format!("{here}\\command"), "/ve", "/d", &format!("\"{exe}\" \"{arg}\""), "/f"])?;

        let pick = format!("{key}\\shell\\02pick");
        reg(&["add", &pick, "/ve", "/d", "解压到指定目录…", "/f"])?;
        reg(&["add", &format!("{pick}\\command"), "/ve", "/d", &format!("\"{exe}\" --pick-dir \"{arg}\""), "/f"])?;
    }
    Ok("已添加右键菜单（仅对文件生效）".into())
}

#[tauri::command]
fn remove_menu() -> Result<String, String> {
    for key in [MENU_KEY, MENU_BG_KEY, MENU_FILE_KEY] {
        let _ = reg(&["delete", key, "/f"]);
    }
    Ok("已移除右键菜单".into())
}

#[tauri::command]
fn reveal(path: String) -> Result<(), String> {
    let p = PathBuf::from(&path);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let mut cmd = std::process::Command::new("explorer.exe");
        if p.is_file() {
            cmd.arg("/select,").arg(&p);
        } else {
            cmd.arg(&p);
        }
        // 不弹黑窗
        cmd.creation_flags(0x0800_0000);
        cmd.spawn().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn main() {
    let (cfg, _settings) = load_settings();
    let config_path = config_path();
    if let Some(parent) = config_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    let pick_dir_on_start = args.iter().any(|a| a == "--pick-dir");
    let initial_paths: Vec<String> = args
        .into_iter()
        .filter(|a| !a.starts_with('-'))
        .filter(|a| Path::new(a).exists())
        .collect();
    let quick_mode = !initial_paths.is_empty();

    tauri::Builder::default()
        .manage(AppState {
            cfg: Mutex::new(cfg),
            running: Arc::new(AtomicBool::new(false)),
            config_path,
            initial_paths,
            pick_dir_on_start,
            quick_mode,
        })
        .setup(move |app| {
            // 旧版菜单同时注册在文件夹和空白处；现在只保留「文件」右键，
            // 启动时顺手清掉旧键，避免用户不重装菜单还在空目录看到它
            for key in [MENU_KEY, MENU_BG_KEY] {
                let _ = reg(&["delete", key, "/f"]);
            }
            // 文件右键已安装过的话，顺手把菜单里的 exe 路径更新成当前这份
            if reg(&["query", MENU_FILE_KEY]).is_ok() {
                let _ = install_menu();
            }
            if quick_mode {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.set_min_size(Some(tauri::LogicalSize::new(520.0, 280.0)));
                    let _ = win.set_size(tauri::LogicalSize::new(600.0, 310.0));
                    let _ = win.set_resizable(false);
                    let _ = win.center();
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_settings,
            save_settings,
            pick_inputs,
            pick_folder,
            pick_save,
            pick_backup,
            vault_export,
            vault_import,
            start_extract,
            detect_paths,
            vault_list,
            vault_add,
            vault_delete,
            vault_stats,
            cleanup_scan,
            cleanup_prune,
            encoding_detail,
            reveal,
            startup_paths,
            startup_pick_dir,
            startup_quick,
            show_window,
            enter_quick,
            win_minimize,
            win_toggle_max,
            win_is_max,
            close_window,
            install_menu,
            remove_menu
        ])
        .run(tauri::generate_context!())
        .expect("启动 Tauri 失败");
}
