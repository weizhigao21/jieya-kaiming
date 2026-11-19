const $ = (sel) => document.querySelector(sel);
const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args || {});

const taskCards = new Map();
let busy = false;
let selectedId = null;
let runDone = 0, runPwd = 0, runFail = 0;
let startedCount = 0, resolvedCount = 0;
let workdirForOpen = "";

 // ---------------- 工具 ----------------
function fmtBytes(n) {
  if (!n && n !== 0) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

function baseName(p) {
  const parts = String(p).split(/[\\/]/);
  return parts[parts.length - 1] || p;
}

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

let toastTimer = null;
function toast(msg) {
  const el = $("#toast");
  el.textContent = msg;
  el.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add("hidden"), 2800);
}

function setStatus(text, state) {
  $("#status").textContent = text;
  const dot = $("#statusdot");
  dot.className = "statusdot" + (state ? " " + state : "");
}

// ---------------- 主题 ----------------
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const use = $("#btn-theme use");
  if (use) use.setAttribute("href", theme === "dark" ? "#i-sun" : "#i-moon");
}
function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem("jieya-theme"); } catch (_) {}
  const preferDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  applyTheme(saved || (preferDark ? "dark" : "light"));
  $("#btn-theme").onclick = () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    applyTheme(next);
    try { localStorage.setItem("jieya-theme", next); } catch (_) {}
  };
}

// ---------------- 统计 ----------------
function updateStats() {
  $("#stat-done").textContent = runDone;
  $("#stat-pwd").textContent = runPwd;
  $("#stat-fail").textContent = runFail;
  const pct = startedCount ? Math.min(100, Math.round((resolvedCount / startedCount) * 100)) : 0;
  $("#run-bar").style.width = pct + "%";
  $("#run-pct").textContent = pct + "%";
}

function resetRun() {
  runDone = runPwd = runFail = 0;
  startedCount = resolvedCount = 0;
  updateStats();
  $("#run-state").textContent = "进行中";
}

// ---------------- 详情 ----------------
function renderDetail(card) {
  const box = $("#detail");
  const openBtn = $("#btn-detail-open");
  if (!card) {
    box.innerHTML = `<p class="detail-empty">选中左侧任务查看详情</p>`;
    openBtn.classList.add("hidden");
    return;
  }
  const d = card.data;
  const rows = [];
  const row = (k, v, mono) => rows.push(`<div class="drow"><span>${k}</span><b class="${mono ? "mono" : ""}">${esc(v)}</b></div>`);
  row("状态", d.statusText || "—");
  row("格式", d.format || "未知");
  row("大小", d.size ? fmtBytes(d.size) : "—");
  row("解压后", d.total ? fmtBytes(d.total) : "—");
  row("文件", d.files != null ? d.files + " 个" : "—");
  if (d.volumes > 1) row("分卷", d.volumes + " 卷");
  row("加密", d.encrypted ? "是" : d.encrypted === false ? "否" : "—");
  row("层级", d.depth > 0 ? `第 ${d.depth + 1} 层` : "顶层");
  if (d.message) row("信息", d.message, true);
  if (d.outDir) row("输出", d.outDir, true);

  box.innerHTML = `
    <div class="dname">${esc(baseName(d.archive))}</div>
    <div class="dpath">${esc(d.archive)}</div>
    <div class="dgrid">${rows.join("")}</div>`;
  openBtn.classList.toggle("hidden", !d.outDir);
  openBtn.onclick = () => d.outDir && invoke("reveal", { path: d.outDir }).catch(() => {});
}

function selectCard(id) {
  selectedId = id;
  taskCards.forEach((c, key) => c.el.classList.toggle("selected", key === id));
  renderDetail(taskCards.get(id) || null);
}

function updateTaskCount() {
  const n = taskCards.size;
  $("#task-count").textContent = `${n} 项`;
  $("#btn-clear-2").style.visibility = n ? "visible" : "hidden";
}

// ---------------- 任务卡 ----------------
function cardFor(id, archive, depth) {
  let card = taskCards.get(id);
  if (card) return card;

  const el = document.createElement("div");
  el.className = "task";
  el.innerHTML = `
    <div class="tstate"><svg class="i"><use href="#i-clock"/></svg></div>
    <div class="tmain">
      <div class="tname"><span class="nm"></span><span class="tag"></span></div>
      <div class="tmeta"></div>
    </div>
    <div class="tright"><span class="tstatus">排队中</span></div>
    <div class="tbar"><i></i></div>
  `;
  el.querySelector(".nm").textContent = baseName(archive);
  el.querySelector(".tag").textContent = depth > 0 ? `第 ${depth + 1} 层` : "";
  el.querySelector(".tag").style.display = depth > 0 ? "" : "none";
  el.querySelector(".tmeta").textContent = String(archive || "");
  el.onclick = () => selectCard(id);

  $("#tasks").appendChild(el);
  $("#empty").classList.add("hidden");

  card = {
    el,
    state: el.querySelector(".tstate"),
    name: el.querySelector(".nm"),
    tag: el.querySelector(".tag"),
    meta: el.querySelector(".tmeta"),
    status: el.querySelector(".tstatus"),
    bar: el.querySelector(".tbar"),
    fill: el.querySelector(".tbar > i"),
    data: {
      archive: archive || "",
      depth: depth || 0,
      statusText: "排队中",
      format: "",
      size: 0,
      total: 0,
      files: null,
      volumes: 0,
      encrypted: null,
      message: "",
      outDir: null,
      progress: 0,
    },
  };
  taskCards.set(id, card);
  updateTaskCount();
  if (selectedId == null) selectCard(id);
  else if (selectedId === id) renderDetail(card);
  return card;
}

function setState(card, kind, text, statusText) {
  card.state.className = "tstate" + (kind ? " " + kind : "");
  card.state.querySelector("use").setAttribute("href", "#i-" + (kind === "done" ? "check" : kind === "failed" ? "alert" : kind === "warn" ? "lock" : "clock"));
  card.status.textContent = text;
  card.status.className = "tstatus" + (kind === "done" ? " ok" : kind === "failed" ? " bad" : kind === "warn" ? " warn" : "");
  card.data.statusText = statusText || text;
}

function handleEvent(ev) {
  if (!ev || !ev.kind) return;
  if (quickMode) { updateQuick(ev); return; }

  if (ev.kind === "summary") {
    busy = false;
    if (ev.error) {
      setStatus("出错：" + ev.error, "bad");
      $("#run-state").textContent = "出错";
      toast("出错：" + ev.error);
      return;
    }
    const parts = [];
    if (ev.extracted) parts.push(`解压 ${ev.extracted} 个`);
    if (ev.needsPassword) parts.push(`待密码 ${ev.needsPassword} 个`);
    if (ev.failed) parts.push(`失败 ${ev.failed} 个`);
    if (ev.skipped) parts.push(`跳过 ${ev.skipped} 个`);
    const text = parts.length ? parts.join("，") : "没有可处理的压缩包";
    $("#summary").classList.remove("hidden");
    $("#summary-text").textContent = `${text} · 用时 ${(ev.elapsedMs / 1000).toFixed(1)} 秒`;
    $("#run-state").textContent = ev.failed ? "有失败" : "已完成";
    setStatus("就绪", ev.failed ? "bad" : "ok");
    return;
  }

  if (ev.kind === "warning") {
    toast(ev.message || "有分卷缺失，已跳过");
    return;
  }

  const card = ev.taskId !== undefined ? cardFor(ev.taskId, ev.archive || "", ev.depth || 0) : null;
  if (!card) return;
  const d = card.data;

  switch (ev.kind) {
    case "started": {
      if (ev.archive) d.archive = ev.archive;
      if (ev.depth != null) d.depth = ev.depth;
      startedCount++;
      setState(card, "running", "处理中", "处理中");
      if (d.depth > 0) { card.tag.textContent = `第 ${d.depth + 1} 层`; card.tag.style.display = ""; }
      updateStats();
      break;
    }
    case "info": {
      d.format = ev.format || "";
      d.size = ev.archiveSize || 0;
      d.total = ev.total || 0;
      d.files = ev.files ?? null;
      d.volumes = ev.volumes || 0;
      d.encrypted = !!ev.encrypted;
      const bits = [];
      if (d.format) bits.push(d.format);
      bits.push(fmtBytes(d.size));
      if (d.total) bits.push("解压后 " + fmtBytes(d.total));
      if (d.files != null) bits.push(d.files + " 个文件");
      if (d.volumes > 1) bits.push(d.volumes + " 卷");
      if (d.encrypted) bits.push("加密");
      card.meta.textContent = bits.join(" · ");
      break;
    }
    case "phase":
      d.message = ev.message || "";
      card.meta.textContent = d.message;
      break;
    case "progress":
      if (!card.bar.classList.contains("failed") && !card.bar.classList.contains("done")) {
        card.fill.style.width = Math.min(100, ev.percent) + "%";
      }
      if (card.state.classList.contains("running")) card.status.textContent = `解压 ${ev.percent}%`;
      break;
    case "renamed":
      d.message = `已修正 ${ev.count} 个乱码文件名` + (ev.encoding ? `（${ev.encoding}）` : "") +
        (ev.sample ? `，例如 ${ev.sample[0]} → ${ev.sample[1]}` : "");
      card.meta.textContent = d.message;
      break;
    case "nested":
      d.message = "发现内层包：" + baseName(ev.archive);
      card.meta.textContent = d.message;
      break;
    case "done": {
      d.outDir = ev.outDir;
      setState(card, "done", "完成", "完成");
      card.bar.classList.add("done");
      card.fill.style.width = "100%";
      card.meta.textContent = "→ " + ev.outDir;
      runDone++;
      resolvedCount++;
      updateStats();
      break;
    }
    case "failed": {
      const pwd = ev.reason && ev.reason.includes("密码");
      setState(card, pwd ? "warn" : "failed", pwd ? "待密码" : "失败", pwd ? "待密码" : "失败");
      card.bar.classList.add("failed");
      card.meta.textContent = ev.reason || "";
      d.message = ev.reason || "";
      if (pwd) runPwd++; else runFail++;
      resolvedCount++;
      updateStats();
      break;
    }
    case "skipped":
      setState(card, "warn", "跳过", "跳过");
      card.meta.textContent = ev.reason || "";
      resolvedCount++;
      updateStats();
      break;
  }
  if (selectedId === ev.taskId) renderDetail(card);
}

// ---------------- 开始解压 ----------------
async function start(paths, destination, password) {
  if (!paths || !paths.length) return;
  if (busy) { toast("已有任务在跑，等它结束"); return; }
  busy = true;
  if (quickMode) {
    quickDest = destination || quickDest || null;
    quickStarted = 0;
    quickDone = 0;
    quickTasks.clear();
    quickFailures = [];
    quickOut = null;
    quickClosing = false;
    $("#quick-name").textContent = paths.length > 1 ? `${paths.length} 个压缩包` : baseName(paths[0]);
    $("#quick-count").textContent = "";
    $("#quick-meta").textContent = "等待开始";
    $("#quick-status").className = "";
    $("#quick-status").textContent = "正在启动…";
    $("#quick-note").textContent = "";
    $("#quick-percent").textContent = "0%";
    $("#quick-fill").className = "quick-fill";
    $("#quick-fill").style.width = "0";
    $("#quick-pwd").classList.add("hidden");
    $("#quick-foot").classList.add("hidden");
    $("#quick-open").classList.add("hidden");
  }
  $("#summary").classList.add("hidden");
  $("#run-state").textContent = "进行中";
  resetRun();
  setStatus("正在解压…", "run");
  try {
    const channel = new window.__TAURI__.core.Channel();
    channel.onmessage = handleEvent;
    await invoke("start_extract", { paths, destination: destination || null, password: password || null, onEvent: channel });
  } catch (e) {
    busy = false;
    setStatus("就绪", "bad");
    toast(String(e));
  }
}

async function pick(folder) {
  try {
    const paths = await invoke("pick_inputs", { folder });
    if (paths && paths.length) start(paths);
  } catch (e) { toast(String(e)); }
}

function clearTasks() {
  $("#tasks").innerHTML = "";
  taskCards.clear();
  selectedId = null;
  $("#summary").classList.add("hidden");
  updateTaskCount();
  $("#empty").classList.remove("hidden");
  resetRun();
  $("#run-state").textContent = "空闲";
  renderDetail(null);
}

// ---------------- 拖拽 ----------------
function initDragDrop() {
  const drop = $("#drop");
  window.addEventListener("dragover", (e) => { e.preventDefault(); });
  window.addEventListener("drop", (e) => { e.preventDefault(); });

  if (!window.__TAURI__) return;
  const win = window.__TAURI__.webviewWindow.getCurrentWebviewWindow();
  win.onDragDropEvent((event) => {
    const p = event.payload;
    if (p.type === "enter" || p.type === "over") drop.classList.add("hover");
    else if (p.type === "leave") drop.classList.remove("hover");
    else if (p.type === "drop") {
      drop.classList.remove("hover");
      start(p.paths);
    }
  });
}

// ---------------- 设置 ----------------
async function openSettings() {
  try {
    const info = await invoke("get_settings");
    const s = info.settings;
    $("#set-sevenzip").value = s.sevenzip || "";
    $("#set-workdir").value = s.workdir || "";
    $("#set-depth").value = s.maxDepth;
    $("#set-pwd").value = s.maxPasswordAttempts;
    $("#set-delete").checked = !!s.deleteIntermediate;
    $("#set-overwrite").checked = !!s.overwriteExisting;
    $("#set-skip").checked = !!s.skipDone;
    $("#env-info").textContent =
      `7z：${info.sevenzipVersion || "未检测到"}（${info.sevenzipOk ? "可用" : "不可用"}）\n` +
      `数据目录：${info.dataDir}\n密码库：${info.vaultPath}`;
    applyEnv(info);
    $("#modal-settings").classList.remove("hidden");
  } catch (e) { toast(String(e)); }
}

function short7z(v) {
  if (!v) return "未找到";
  const m = String(v).match(/7-Zip\s+([\d.]+)(?:\s*\((x64|x86)\))?/i);
  if (m) return m[1] + (m[2] ? ` (${m[2]})` : "");
  return String(v).slice(0, 20);
}

function applyEnv(info) {
  $("#env").textContent = `v${info.version} · ${info.sevenzipOk ? "7z 就绪" : "7z 缺失"}`;
  if ($("#env-version")) $("#env-version").textContent = "v" + info.version;
  if ($("#env-7z")) $("#env-7z").textContent = info.sevenzipOk ? short7z(info.sevenzipVersion) : "未找到";
  workdirForOpen = (info.settings && info.settings.workdir) || info.dataDir || "";
  if ($("#env-workdir")) {
    $("#env-workdir").textContent = workdirForOpen || "—";
    $("#env-workdir").title = workdirForOpen || "";
  }
}

async function saveSettings() {
  const settings = {
    sevenzip: $("#set-sevenzip").value.trim(),
    workdir: $("#set-workdir").value.trim(),
    maxDepth: Number($("#set-depth").value) || 5,
    maxPasswordAttempts: Number($("#set-pwd").value) || 20,
    deleteIntermediate: $("#set-delete").checked,
    overwriteExisting: $("#set-overwrite").checked,
    skipDone: $("#set-skip").checked,
  };
  try {
    const info = await invoke("save_settings", { settings });
    applyEnv(info);
    $("#modal-settings").classList.add("hidden");
    toast("设置已保存");
  } catch (e) { toast(String(e)); }
}

// ---------------- 密码库 ----------------
async function loadVault() {
  try {
    const keyword = $("#vault-search").value.trim();
    const rows = await invoke("vault_list", { keyword, limit: 500 });
    const stats = await invoke("vault_stats");
    $("#vault-count").textContent = `${stats.count} 条`;
    const box = $("#vault-rows");
    box.innerHTML = "";
    if (!rows.length) {
      box.innerHTML = `<div class="row"><span>暂无记录</span><span></span><span></span><span></span></div>`;
    }
    for (const r of rows) {
      const row = document.createElement("div");
      row.className = "row";
      row.innerHTML = `<span></span><span></span><span></span><button>删除</button>`;
      row.children[0].textContent = r.password;
      row.children[1].textContent = r.source || "-";
      row.children[2].textContent = r.hitCount ?? 0;
      row.children[3].onclick = async () => {
        try {
          await invoke("vault_delete", { id: r.id });
          loadVault();
        } catch (e) { toast(String(e)); }
      };
      box.appendChild(row);
    }
  } catch (e) { toast(String(e)); }
}

async function addVault() {
  const password = $("#vault-new-pwd").value;
  if (!password.trim()) { toast("密码不能为空"); return; }
  try {
    await invoke("vault_add", { password, source: $("#vault-new-src").value });
    $("#vault-new-pwd").value = "";
    $("#vault-new-src").value = "";
    loadVault();
  } catch (e) { toast(String(e)); }
}

async function exportVault() {
  const pass = $("#vault-backup-pass").value;
  if (!pass.trim()) { toast("先填备份口令"); return; }
  try {
    const today = new Date().toISOString().slice(0, 10);
    const dest = await invoke("pick_save", { defaultName: `passwords-${today}.vault` });
    if (!dest) return;
    const r = await invoke("vault_export", { dest, password: pass });
    toast(`已导出 ${r.entries} 条 → ${r.path}`);
  } catch (e) { toast(String(e)); }
}

async function importVault() {
  const pass = $("#vault-backup-pass").value;
  if (!pass.trim()) { toast("先填备份口令"); return; }
  try {
    const src = await invoke("pick_backup");
    if (!src) return;
    const r = await invoke("vault_import", { src, password: pass });
    toast(`合并完成：新增 ${r.added} 条，更新 ${r.merged} 条，共 ${r.total} 条`);
    loadVault();
  } catch (e) { toast(String(e)); }
}

// ---------------- 清理 ----------------
let cleanItems = [];

async function scanClean() {
  try {
    const data = await invoke("cleanup_scan");
    cleanItems = data.items || [];
    $("#clean-head").textContent =
      `工作目录：${data.workdir} · 合计 ${cleanItems.length} 项，${fmtBytes(data.totalBytes)}`;
    const list = $("#clean-list");
    list.innerHTML = "";
    if (!cleanItems.length) {
      list.innerHTML = `<p class="hint">没有残留，很干净。</p>`;
      return;
    }
    cleanItems.forEach((item, idx) => {
      const el = document.createElement("div");
      el.className = "clean-item" + (item.safe ? "" : " danger");
      el.innerHTML = `
        <input type="checkbox" ${item.safe ? "checked" : ""} data-idx="${idx}" />
        <div><strong></strong><small></small></div>
        <span class="size"></span>`;
      el.querySelector("strong").textContent = `${item.kind} · ${item.path}`;
      el.querySelector("small").textContent = item.reason;
      el.querySelector(".size").textContent = fmtBytes(item.size);
      list.appendChild(el);
    });
  } catch (e) { toast(String(e)); }
}

async function pruneClean() {
  const checked = Array.from(document.querySelectorAll("#clean-list input[type=checkbox]:checked"))
    .map((c) => cleanItems[Number(c.dataset.idx)]);
  if (!checked.length) { toast("先勾选要清理的项"); return; }
  const allowUnsafe = checked.some((i) => !i.safe);
  try {
    const res = await invoke("cleanup_prune", {
      allowUnsafe,
      paths: checked.map((i) => i.path),
    });
    toast(`已释放 ${fmtBytes(res.freed)}` + (res.errors && res.errors.length ? `，${res.errors.length} 项被跳过` : ""));
    scanClean();
  } catch (e) { toast(String(e)); }
}

// ---------------- 弹层入口 ----------------
function openVault() {
  $("#modal-vault").classList.remove("hidden");
  loadVault();
}

function openClean() {
  $("#modal-clean").classList.remove("hidden");
  scanClean();
}

// ---------------- 右键小窗模式 ----------------
let quickMode = false;
let quickOut = null;
let quickDest = null;
let quickClosing = false;
let quickStarted = 0;
let quickDone = 0;
const quickTasks = new Map();
let quickFailures = [];

function closeQuick() {
  if (quickClosing) return;
  quickClosing = true;
  invoke("close_window").catch(() => {});
}

function showQuickControls() {
  const hasOut = !!quickOut;
  $("#quick-open").classList.toggle("hidden", !hasOut);
  $("#quick-foot").classList.toggle("hidden", !hasOut);
}

function showQuickPassword(note) {
  $("#quick-status").className = "bad";
  $("#quick-status").textContent = "需要密码";
  $("#quick-note").textContent = note || "这个压缩包有密码，输入后点解锁";
  $("#quick-pwd").classList.remove("hidden");
  showQuickControls();
  setTimeout(() => $("#quick-pwd-input").focus(), 0);
}

function quickMeta(ev) {
  const bits = [];
  if (ev.format) bits.push(ev.format);
  if (ev.archiveSize) bits.push(fmtBytes(ev.archiveSize));
  if (ev.total) bits.push("解压后 " + fmtBytes(ev.total));
  if (ev.files != null) bits.push(ev.files + " 个文件");
  if (ev.volumes > 1) bits.push(ev.volumes + " 卷");
  if (ev.encrypted) bits.push("加密");
  $("#quick-meta").textContent = bits.join(" · ") || "正在读取压缩包…";
}

function updateQuick(ev) {
  const fill = $("#quick-fill");
  const status = $("#quick-status");
  const percent = $("#quick-percent");
  const note = $("#quick-note");

  if (ev.kind === "summary") {
    busy = false;
    $("#quick-count").textContent = ev.elapsedMs
      ? `${quickDone}/${quickStarted} · ${(ev.elapsedMs / 1000).toFixed(1)} 秒`
      : "";
    if (ev.error) {
      fill.className = "quick-fill bad";
      fill.style.width = "100%";
      percent.textContent = "—";
      status.className = "bad";
      status.textContent = "出错";
      note.textContent = ev.error;
      showQuickControls();
      return;
    }
    const parts = [];
    if (ev.extracted) parts.push(`解压 ${ev.extracted} 个`);
    if (ev.needsPassword) parts.push(`待密码 ${ev.needsPassword} 个`);
    if (ev.failed) parts.push(`失败 ${ev.failed} 个`);
    if (ev.skipped) parts.push(`跳过 ${ev.skipped} 个`);
    const ok = ev.extracted > 0 && !ev.failed && !ev.needsPassword;
    status.textContent = parts.length ? parts.join("，") : "没有可处理的压缩包";
    status.className = ok ? "ok" : "bad";
    fill.className = "quick-fill" + (ok ? " done" : " bad");
    fill.style.width = "100%";
    percent.textContent = ok ? "100%" : "—";

    if (ev.needsPassword && !quickFailures.length) {
      for (const archive of quickTasks.values()) quickFailures.push({ archive });
    }
    if (ok) {
      $("#quick-pwd").classList.add("hidden");
      $("#quick-open").classList.add("hidden");
      $("#quick-foot").classList.add("hidden");
      setTimeout(closeQuick, 1500);
    } else if (quickFailures.length) {
      showQuickPassword(note.textContent || "有压缩包需要密码");
    } else {
      showQuickControls();
    }
    return;
  }

  if (ev.kind === "warning") {
    note.textContent = ev.message || "有分卷缺失，已跳过";
    return;
  }
  if (ev.kind === "renamed") {
    note.textContent = `已修正 ${ev.count} 个乱码文件名` + (ev.encoding ? `（${ev.encoding}）` : "");
    return;
  }
  if (ev.kind === "nested") {
    note.textContent = "发现内层包：" + baseName(ev.archive || "");
    return;
  }
  if (ev.taskId == null) return;

  switch (ev.kind) {
    case "started": {
      quickStarted++;
      quickTasks.set(ev.taskId, ev.archive || "");
      $("#quick-name").textContent = baseName(ev.archive || "") || "解压中…";
      $("#quick-count").textContent = `${quickStarted} 个任务`;
      $("#quick-meta").textContent = "正在读取压缩包…";
      fill.className = "quick-fill";
      fill.style.width = "0";
      percent.textContent = "0%";
      status.className = "";
      status.textContent = "正在解压";
      note.textContent = "";
      $("#quick-pwd").classList.add("hidden");
      $("#quick-open").classList.add("hidden");
      $("#quick-foot").classList.add("hidden");
      break;
    }
    case "info":
      quickMeta(ev);
      break;
    case "phase":
      note.textContent = ev.message || "处理中…";
      status.textContent = "处理中";
      break;
    case "progress":
      fill.style.width = Math.min(100, ev.percent) + "%";
      percent.textContent = `${ev.percent}%`;
      status.textContent = "解压中";
      break;
    case "done":
      quickDone++;
      quickOut = ev.outDir || quickOut;
      fill.className = "quick-fill done";
      fill.style.width = "100%";
      percent.textContent = "100%";
      status.className = "ok";
      status.textContent = "完成";
      note.textContent = "→ " + (ev.outDir || "");
      $("#quick-count").textContent = `${quickDone}/${quickStarted} 个任务`;
      break;
    case "failed": {
      const archive = quickTasks.get(ev.taskId) || "";
      const raw = ev.reason || "失败";
      const isPwd = /密码|password/i.test(raw);
      const reason = isPwd
        ? "压缩包已加密，输入正确密码后重试"
        : raw.replace(/\s+/g, " ").slice(0, 180);
      fill.className = "quick-fill bad";
      status.className = "bad";
      status.textContent = isPwd ? "需要密码" : "失败";
      note.textContent = reason;
      quickOut = null;
      if (isPwd && archive && !quickFailures.some((f) => f.archive === archive)) {
        quickFailures.push({ archive });
      }
      if (isPwd) showQuickPassword(reason);
      else showQuickControls();
      break;
    }
  }
}

function retryQuick(ev) {
  if (ev) ev.preventDefault();
  const pwd = $("#quick-pwd-input").value.trim();
  if (!pwd) return;
  const targets = quickFailures.map((f) => f.archive).filter(Boolean);
  if (!targets.length) return;
  $("#quick-pwd").classList.add("hidden");
  $("#quick-pwd-input").value = "";
  quickStarted = 0;
  quickDone = 0;
  quickTasks.clear();
  quickFailures = [];
  quickOut = null;
  quickClosing = false;
  busy = false;
  start(targets, quickDest, pwd);
}

async function initQuick() {
  quickMode = true;
  document.body.classList.add("quick");
  $("#quick").classList.remove("hidden");
  $("#quick-open").onclick = () => {
    if (quickOut) invoke("reveal", { path: quickOut }).catch((e) => toast(String(e)));
  };
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && quickMode) closeQuick();
  });
  $("#quick-pwd").onsubmit = retryQuick;
  // 等窗口缩成小窗再显示，避免先闪出主界面
  await invoke("enter_quick").catch(() => {});
}

async function revealWindow() {
  // 隐藏窗口里 requestAnimationFrame 可能不触发，用短定时器等一帧布局再显示
  await new Promise((resolve) => setTimeout(resolve, 40));
  await invoke("show_window").catch(() => {});
}

// ---------------- 绑定 ----------------
function initWindowControls() {
  document.querySelectorAll("[data-win]").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const act = btn.dataset.win;
      if (act === "min") {
        invoke("win_minimize").catch(() => {});
      } else if (act === "max") {
        await invoke("win_toggle_max").catch(() => {});
        syncWinMax();
      } else {
        invoke("close_window").catch(() => {});
      }
    });
  });
  syncWinMax();
}

function initWindowDrag() {
  if (!window.__TAURI__) return;
  const win = window.__TAURI__.webviewWindow.getCurrentWebviewWindow();
  const interactive = (t) => t.closest("button, a, input, select, textarea, .menu-wrap, .win-controls");
  document.querySelectorAll(".topbar, .quick-head").forEach((bar) => {
    bar.addEventListener("pointerdown", (e) => {
      if (e.button !== 0 || e.isPrimary === false) return;
      if (interactive(e.target)) return;
      win.startDragging().catch(() => {});
    });
  });
}

async function syncWinMax() {
  const max = await invoke("win_is_max").catch(() => false);
  document.querySelectorAll(".win-max use").forEach((u) => {
    u.setAttribute("href", max ? "#i-restore" : "#i-max");
  });
}

function initUi() {
  initTheme();
  initWindowControls();
  initWindowDrag();

  $("#btn-files").onclick = () => pick(false);
  $("#btn-folder").onclick = () => pick(true);
  $("#btn-save-settings").onclick = saveSettings;

  // 「更多」菜单：把密码库/清理/设置收进一个入口
  const moreBtn = $("#btn-more");
  const moreMenu = $("#more-menu");
  const closeMore = () => {
    moreMenu.classList.add("hidden");
    moreBtn.setAttribute("aria-expanded", "false");
  };
  moreBtn.onclick = (e) => {
    e.stopPropagation();
    const open = moreMenu.classList.toggle("hidden");
    moreBtn.setAttribute("aria-expanded", open ? "false" : "true");
  };
  moreMenu.onclick = (e) => {
    const item = e.target.closest(".menu-item");
    if (!item) return;
    closeMore();
    const cmd = item.dataset.cmd;
    if (cmd === "vault") openVault();
    else if (cmd === "clean") openClean();
    else if (cmd === "settings") openSettings();
  };
  document.addEventListener("click", (e) => {
    if (!moreMenu.classList.contains("hidden") && !e.target.closest(".menu-wrap")) closeMore();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeMore();
  });

  $("#btn-vault-refresh").onclick = loadVault;
  $("#vault-search").addEventListener("input", () => loadVault());
  $("#btn-vault-add").onclick = addVault;
  $("#btn-vault-export").onclick = exportVault;
  $("#btn-vault-import").onclick = importVault;
  $("#btn-clean-scan").onclick = scanClean;
  $("#btn-clean-prune").onclick = pruneClean;
  $("#btn-menu-install").onclick = async () => {
    try { toast(await invoke("install_menu")); } catch (e) { toast(String(e)); }
  };
  $("#btn-menu-remove").onclick = async () => {
    try { toast(await invoke("remove_menu")); } catch (e) { toast(String(e)); }
  };
  $("#btn-clear-2").onclick = clearTasks;
  $("#btn-open-workdir").onclick = () => {
    if (workdirForOpen) invoke("reveal", { path: workdirForOpen }).catch(() => {});
    else toast("还没有工作目录");
  };

  document.querySelectorAll("[data-close]").forEach((btn) => {
    btn.onclick = () => btn.closest(".modal").classList.add("hidden");
  });
  document.querySelectorAll(".modal").forEach((m) => {
    m.addEventListener("click", (e) => { if (e.target === m) m.classList.add("hidden"); });
  });

  initDragDrop();
  updateStats();
  updateTaskCount();
  renderDetail(null);

  // 启动时拉一次环境信息（顺带校验 7z）
  // 放到窗口显示之后：检测 7z 会起进程，别让它拖慢首帧

  // 右键菜单会带路径进来：小窗显示进度，正常完成自动关；
  // 「解压到指定目录」先弹目录选择
  Promise.all([invoke("startup_paths"), invoke("startup_pick_dir"), invoke("startup_quick")])
    .then(async ([paths, needPick, quick]) => {
      if (quick && paths && paths.length) {
        await initQuick();
        $("#quick-name").textContent = paths.length > 1 ? `${paths.length} 个压缩包` : baseName(paths[0]);
      }
      await revealWindow();
      if (!quickMode) invoke("get_settings").then(applyEnv).catch(() => {});
      if (!paths || !paths.length) return;
      if (needPick) {
        const dest = await invoke("pick_folder").catch(() => null);
        if (!dest) {
          if (quickMode) {
            $("#quick-status").textContent = "已取消";
            showQuickControls();
          } else {
            toast("已取消");
          }
          return;
        }
        start(paths, dest);
      } else {
        start(paths);
      }
    })
    .catch(async () => { await revealWindow(); });
}

document.addEventListener("DOMContentLoaded", initUi);
