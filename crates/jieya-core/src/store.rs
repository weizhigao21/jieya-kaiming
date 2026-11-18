//! 任务表 SQLite 存储，含状态迁移校验。
//!
//! 表结构与原版 `core/store.py` **逐字段一致**（同一张 `tasks` 表、同一个
//! `jieya.db`），老库可以直接打开；老库缺列时按同样的两条 ALTER 补齐。
//!
//! 为什么状态迁移要校验：任务表是界面唯一的历史真相，`done` 之后再写
//! `extracting` 会让「已完成」的目录被当成仍在处理，清理逻辑据此就会保留
//! 一堆本可回收的残留。

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};

use crate::models::{now_iso, Task, TaskStatus};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    archive_path TEXT NOT NULL,
    archive_fingerprint TEXT NOT NULL DEFAULT '',
    parent_id INTEGER,
    depth INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    password_used TEXT,
    error TEXT NOT NULL DEFAULT '',
    extracted_dir TEXT NOT NULL DEFAULT '',
    delivery_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
";

/// 老库补列：`CREATE TABLE IF NOT EXISTS` 对已存在的表是空操作，加列必须显式 ALTER。
const COLUMN_MIGRATIONS: [(&str, &str); 2] = [
    (
        "archive_fingerprint",
        "ALTER TABLE tasks ADD COLUMN archive_fingerprint TEXT NOT NULL DEFAULT ''",
    ),
    (
        "delivery_error",
        "ALTER TABLE tasks ADD COLUMN delivery_error TEXT NOT NULL DEFAULT ''",
    ),
];

const SELECT_COLS: &str = "id, archive_path, archive_fingerprint, parent_id, depth, source, status, \
     password_used, error, extracted_dir, delivery_error, created_at, updated_at";

/// 数据库里的一行任务（比运行期的 [`Task`] 多出时间戳与来源）。
#[derive(Debug, Clone)]
pub struct StoredTask {
    pub id: i64,
    pub archive_path: String,
    pub archive_fingerprint: String,
    pub parent_id: Option<i64>,
    pub depth: u32,
    pub source: String,
    pub status: TaskStatus,
    pub password_used: Option<String>,
    pub error: String,
    pub extracted_dir: String,
    pub delivery_error: String,
    pub created_at: String,
    pub updated_at: String,
}

impl StoredTask {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            archive_path: row.get(1)?,
            archive_fingerprint: row.get(2)?,
            parent_id: row.get(3)?,
            depth: row.get::<_, i64>(4)? as u32,
            source: row.get(5)?,
            status: TaskStatus::from_str(&row.get::<_, String>(6)?),
            password_used: row.get(7)?,
            error: row.get(8)?,
            extracted_dir: row.get(9)?,
            delivery_error: row.get(10)?,
            created_at: row.get(11)?,
            updated_at: row.get(12)?,
        })
    }
}

pub struct TaskStore {
    conn: Connection,
    path: PathBuf,
}

impl TaskStore {
    pub fn open(db_path: &Path) -> crate::Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(db_path)
            .map_err(|e| crate::Error::Other(format!("打开任务库失败: {e}")))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| crate::Error::Other(format!("建表失败: {e}")))?;
        let mut store = Self {
            conn,
            path: db_path.to_path_buf(),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> crate::Result<()> {
        let mut stmt = self
            .conn
            .prepare("PRAGMA table_info(tasks)")
            .map_err(other)?;
        let have: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(other)?
            .filter_map(|r| r.ok())
            .collect();
        for (name, ddl) in COLUMN_MIGRATIONS {
            if !have.iter().any(|c| c == name) {
                self.conn.execute(ddl, []).map_err(other)?;
                eprintln!("任务库补列: {name}");
            }
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 入库一条任务，返回数据库分配的 id（调用方应把它写回 `task.id`）。
    pub fn create(&mut self, task: &mut Task, source: &str) -> crate::Result<i64> {
        let now = now_iso();
        self.conn
            .execute(
                "INSERT INTO tasks(archive_path, archive_fingerprint, parent_id, depth, source, \
                 status, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                params![
                    path_str(&task.archive),
                    task.archive_fingerprint,
                    task.parent_id.map(|p| p as i64),
                    task.depth as i64,
                    source,
                    task.status.as_str(),
                    now,
                    now,
                ],
            )
            .map_err(other)?;
        let id = self.conn.last_insert_rowid();
        task.id = id.max(0) as u64;
        Ok(id)
    }

    /// 更新状态与产物信息；非法迁移直接报错，不写库。
    pub fn update(&mut self, task: &Task) -> crate::Result<()> {
        let old: Option<String> = self
            .conn
            .query_row(
                "SELECT status FROM tasks WHERE id=?1",
                params![task.id as i64],
                |row| row.get(0),
            )
            .ok();
        if let Some(prev) = old {
            TaskStatus::from_str(&prev).require_transition(task.status)?;
        }
        let now = now_iso();
        self.conn
            .execute(
                "UPDATE tasks SET status=?1, password_used=?2, error=?3, extracted_dir=?4, \
                 delivery_error=?5, updated_at=?6 WHERE id=?7",
                params![
                    task.status.as_str(),
                    task.password,
                    task.error.clone().unwrap_or_default(),
                    task.out_dir
                        .as_ref()
                        .map(|p| path_str(p.as_path()))
                        .unwrap_or_default(),
                    task.delivery_error,
                    now,
                    task.id as i64,
                ],
            )
            .map_err(other)?;
        Ok(())
    }

    pub fn get(&self, task_id: i64) -> crate::Result<Option<StoredTask>> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {SELECT_COLS} FROM tasks WHERE id=?1"))
            .map_err(other)?;
        let mut rows = stmt.query(params![task_id]).map_err(other)?;
        match rows.next().map_err(other)? {
            Some(row) => Ok(Some(StoredTask::from_row(row).map_err(other)?)),
            None => Ok(None),
        }
    }

    /// 该路径**最近一次**结论为 DONE 的记录（供幂等跳过判定）。
    ///
    /// 取"最近一次"而不是"有没有成功过"：同一路径可能反复处理，最近一次失败
    /// 就该重做，不能被更早的成功记录骗过去。
    pub fn find_done(&self, archive_path: &str) -> crate::Result<Option<StoredTask>> {
        let mut stmt = self
            .conn
            .prepare(&format!(
                "SELECT {SELECT_COLS} FROM tasks WHERE archive_path=?1 ORDER BY id DESC LIMIT 1"
            ))
            .map_err(other)?;
        let mut rows = stmt.query(params![archive_path]).map_err(other)?;
        match rows.next().map_err(other)? {
            Some(row) => {
                let task = StoredTask::from_row(row).map_err(other)?;
                Ok(if task.status == TaskStatus::Done {
                    Some(task)
                } else {
                    None
                })
            }
            None => Ok(None),
        }
    }

    pub fn list_all(&self) -> crate::Result<Vec<StoredTask>> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {SELECT_COLS} FROM tasks ORDER BY id"))
            .map_err(other)?;
        let rows = stmt.query_map([], |row| StoredTask::from_row(row)).map_err(other)?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn count(&self) -> crate::Result<usize> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get(0))
            .map_err(other)?;
        Ok(n as usize)
    }
}

fn other(e: impl std::fmt::Display) -> crate::Error {
    crate::Error::Other(e.to_string())
}

fn path_str(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "jieya_store_{tag}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64 % 1_000_000_000)
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("t.db")
    }

    /// 走完 pending → probing → extracting，让后续迁移合法
    fn advance(store: &mut TaskStore, task: &mut Task) {
        task.status = TaskStatus::Probing;
        store.update(task).unwrap();
        task.status = TaskStatus::Extracting;
        store.update(task).unwrap();
    }

    #[test]
    fn create_update_and_find_done() {
        let db = temp_db("basic");
        let mut store = TaskStore::open(&db).unwrap();
        let mut task = Task::new(0, PathBuf::from(r"D:\a.zip"), 0, None);
        let id = store.create(&mut task, "example.com").unwrap();
        assert_eq!(task.id as i64, id);

        advance(&mut store, &mut task);
        task.status = TaskStatus::Done;
        task.out_dir = Some(PathBuf::from(r"D:\a"));
        store.update(&task).unwrap();

        let row = store.get(id).unwrap().unwrap();
        assert_eq!(row.status, TaskStatus::Done);
        assert!(store.find_done(r"D:\a.zip").unwrap().is_some());
        assert_eq!(store.count().unwrap(), 1);

        let _ = std::fs::remove_dir_all(db.parent().unwrap());
    }

    #[test]
    fn illegal_transition_is_rejected() {
        let db = temp_db("transition");
        let mut store = TaskStore::open(&db).unwrap();
        let mut task = Task::new(0, PathBuf::from(r"D:\b.zip"), 0, None);
        store.create(&mut task, "").unwrap();
        advance(&mut store, &mut task);
        task.status = TaskStatus::Done;
        store.update(&task).unwrap();

        // done 不能回到 extracting
        task.status = TaskStatus::Extracting;
        assert!(store.update(&task).is_err());
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
    }

    #[test]
    fn failed_then_rerun_is_allowed() {
        let db = temp_db("retry");
        let mut store = TaskStore::open(&db).unwrap();
        let mut task = Task::new(0, PathBuf::from(r"D:\c.zip"), 0, None);
        store.create(&mut task, "").unwrap();
        task.status = TaskStatus::Failed;
        store.update(&task).unwrap();
        task.status = TaskStatus::Pending;
        assert!(store.update(&task).is_ok());
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
    }

    #[test]
    fn only_latest_done_counts() {
        let db = temp_db("latest");
        let mut store = TaskStore::open(&db).unwrap();
        let mut first = Task::new(0, PathBuf::from(r"D:\d.zip"), 0, None);
        store.create(&mut first, "").unwrap();
        advance(&mut store, &mut first);
        first.status = TaskStatus::Done;
        store.update(&first).unwrap();

        // 同一路径又来一次，最近一条失败
        let mut second = Task::new(0, PathBuf::from(r"D:\d.zip"), 0, None);
        store.create(&mut second, "").unwrap();
        second.status = TaskStatus::Failed;
        store.update(&second).unwrap();
        assert!(store.find_done(r"D:\d.zip").unwrap().is_none());
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
    }
}
