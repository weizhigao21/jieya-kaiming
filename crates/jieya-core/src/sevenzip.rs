use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub struct SevenZip {
    exe: PathBuf,
    pub list_timeout: Duration,
    pub extract_timeout: Duration,
}

impl SevenZip {
    pub fn new(exe: impl Into<PathBuf>, list_timeout_secs: u64, extract_timeout_secs: u64) -> Self {
        Self {
            exe: exe.into(),
            list_timeout: Duration::from_secs(list_timeout_secs),
            extract_timeout: Duration::from_secs(extract_timeout_secs),
        }
    }

    fn spawn(&self, args: &[String]) -> Result<std::process::Child> {
        let mut cmd = Command::new(&self.exe);
        cmd.args(args)
            .arg("-y")
            .arg("-sccUTF-8")
            .arg("-spd")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        cmd.spawn()
            .map_err(|e| Error::SevenZip(format!("无法启动 7z: {e}")))
    }

    /// 统一入口：起进程、收输出、带超时兜底。
    pub fn run(&self, args: &[String], timeout: Duration) -> Result<(i32, String, String)> {
        let mut child = self.spawn(args)?;
        let mut out = child.stdout.take().expect("stdout piped");
        let mut err = child.stderr.take().expect("stderr piped");

        let out_handle = thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = out.read_to_end(&mut buf);
            buf
        });
        let err_handle = thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = err.read_to_end(&mut buf);
            buf
        });

        let deadline = Instant::now() + timeout;
        let code = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.code().unwrap_or(-1),
                Ok(None) => {}
                Err(e) => {
                    let _ = child.kill();
                    return Err(Error::SevenZip(format!("等待 7z 失败: {e}")));
                }
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::SevenZip(format!(
                    "7z 执行超时({}s): {} ...",
                    timeout.as_secs(),
                    args.first().map(|s| s.as_str()).unwrap_or("")
                )));
            }
            thread::sleep(Duration::from_millis(50));
        };

        let out = out_handle.join().unwrap_or_default();
        let err = err_handle.join().unwrap_or_default();
        Ok((code, decode(&out), decode(&err)))
    }

    pub fn version(&self) -> Result<String> {
        // 无参数时 7z 只打帮助并以非零码退出，所以从两路输出里找版本行
        let (_code, out, err) = self.run(&[], Duration::from_secs(30))?;
        let text = format!("{out}\n{err}");
        for line in text.lines() {
            let t = line.trim();
            if t.contains("7-Zip") && (t.contains("ersion") || t.len() < 120) {
                return Ok(t.to_string());
            }
        }
        Err(Error::SevenZip("7z 版本探测失败".into()))
    }

    pub fn list_raw(&self, archive: &Path, password: &str) -> Result<(i32, String, String)> {
        self.run(
            &[
                "l".into(),
                "-slt".into(),
                format!("-p{password}"),
                archive.display().to_string(),
            ],
            self.list_timeout,
        )
    }

    pub fn test(&self, archive: &Path, password: &str) -> Result<i32> {
        let (code, _, _) = self.run(
            &[
                "t".into(),
                format!("-p{password}"),
                archive.display().to_string(),
            ],
            self.list_timeout,
        )?;
        Ok(code)
    }

    /// 流式解压：`on_progress(percent)` 增量回调，`cancel` 为真时杀掉 7z。
    pub fn extract(
        &self,
        archive: &Path,
        dest: &Path,
        password: &str,
        on_progress: Option<&dyn Fn(u8)>,
        cancel: Option<Arc<AtomicBool>>,
    ) -> Result<(i32, String)> {
        std::fs::create_dir_all(dest)?;
        let mut child = self.spawn(&[
            "x".into(),
            format!("-o{}", dest.display()),
            format!("-p{password}"),
            archive.display().to_string(),
            "-bsp1".into(),
        ])?;

        let mut out = child.stdout.take().expect("stdout piped");
        let mut err = child.stderr.take().expect("stderr piped");
        // 进度通过 channel 回传：读线程只负责解析与发送，回调在主线程执行，
        // 避免把 &dyn Fn 跨线程共享。
        //
        // stderr 也必须读：7z 把 "ERROR: Wrong password" 这类判定性信息写在
        // stderr 上，不读就等于把"密码错误"误判成"解压失败"，而且管道写满后
        // 子进程会直接卡死。
        let (tx, rx) = std::sync::mpsc::channel::<i16>();
        let out_handle = thread::spawn(move || {
            let mut text = Vec::new();
            let mut chunk = [0u8; 4096];
            let mut last_pct: i16 = -1;
            while let Ok(n) = out.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let data = &chunk[..n];
                text.extend_from_slice(data);
                for pct in parse_percents(data) {
                    if pct != last_pct {
                        last_pct = pct;
                        let _ = tx.send(pct);
                    }
                }
            }
            text
        });
        let err_handle = thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = err.read_to_end(&mut buf);
            buf
        });

        let deadline = Instant::now() + self.extract_timeout;
        let code = loop {
            while let Ok(pct) = rx.try_recv() {
                if let Some(cb) = on_progress {
                    cb(pct.clamp(0, 100) as u8);
                }
            }
            if let Some(flag) = &cancel {
                if flag.load(Ordering::Relaxed) {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = out_handle.join();
                    return Err(Error::Cancelled);
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => break status.code().unwrap_or(-1),
                Ok(None) => {}
                Err(e) => {
                    let _ = child.kill();
                    return Err(Error::SevenZip(format!("等待 7z 失败: {e}")));
                }
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = out_handle.join();
                return Err(Error::SevenZip(format!(
                    "7z 执行超时({}s): extract {}",
                    self.extract_timeout.as_secs(),
                    archive.display()
                )));
            }
            thread::sleep(Duration::from_millis(200));
        };

        let text = out_handle.join().unwrap_or_default();
        let err_bytes = err_handle.join().unwrap_or_default();
        let mut merged = decode(&text);
        if !err_bytes.is_empty() {
            merged.push('\n');
            merged.push_str(&decode(&err_bytes));
        }
        Ok((code, merged))
    }
}

/// 7z 输出按 UTF-8 解码，失败退回 GBK（与 Python 版一致）。
fn decode(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    let (cow, _, _) = encoding_rs::GBK.decode(bytes);
    cow.into_owned()
}

fn parse_percents(data: &[u8]) -> Vec<i16> {
    let mut out = Vec::new();
    let mut num: Option<i16> = None;
    for &b in data {
        if b.is_ascii_digit() {
            let d = (b - b'0') as i16;
            num = Some(num.unwrap_or(0).saturating_mul(10).saturating_add(d).min(100));
        } else if b == b'%' {
            if let Some(v) = num.take() {
                out.push(v);
            }
        } else {
            num = None;
        }
    }
    out
}
