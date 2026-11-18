//! 密码库：SQLite 存储，按来源分组记录成功密码与命中次数。
//!
//! 表结构与 Python 版完全一致，因此**可以直接打开原版的 `data/jieya.db`**，
//! 老用户的密码一条都不用重新积累。

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{Error, Result};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    hit_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_hit_at TEXT,
    UNIQUE(password, source)
);
"#;

const SCAN_CAP: i64 = 2000;

#[derive(Debug, Clone)]
pub struct Entry {
    pub id: i64,
    pub password: String,
    pub source: String,
    pub hit_count: i64,
    pub created_at: String,
    pub last_hit_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SourceStat {
    pub source: String,
    pub count: i64,
    pub total_hits: i64,
}

pub struct Vault {
    conn: Connection,
}

impl Vault {
    pub fn open(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(db_path)
            .map_err(|e| Error::Config(format!("打开密码库失败: {e}")))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
            .ok();
        conn.execute_batch(SCHEMA)
            .map_err(|e| Error::Config(format!("初始化密码库失败: {e}")))?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| Error::Config(format!("打开密码库失败: {e}")))?;
        conn.execute_batch(SCHEMA).ok();
        Ok(Self { conn })
    }

    /// 默认库位置：与 Python 版冻结后一致（%LOCALAPPDATA%\解压开镜\data\jieya.db）
    pub fn default_path() -> PathBuf {
        let base = std::env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        base.join("解压开镜").join("data").join("jieya.db")
    }

    pub fn record_success(&self, password: &str, source: &str) -> Result<()> {
        let now = now_iso();
        self.conn
            .execute(
                "INSERT INTO passwords(password, source, hit_count, created_at, last_hit_at)
                 VALUES(?1, ?2, 1, ?3, ?3)
                 ON CONFLICT(password, source)
                 DO UPDATE SET hit_count = hit_count + 1, last_hit_at = excluded.last_hit_at",
                params![password, source, now],
            )
            .map_err(|e| Error::Config(format!("写入密码库失败: {e}")))?;
        Ok(())
    }

    pub fn add_manual(&self, password: &str, source: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO passwords(password, source, hit_count, created_at)
                 VALUES(?1, ?2, 0, ?3)",
                params![password, source, now_iso()],
            )
            .map_err(|e| Error::Config(format!("写入密码库失败: {e}")))?;
        Ok(())
    }

    /// 合并导入：同一条（密码 + 来源）不重复，命中数取较大值，最后命中时间取较晚的。
    /// 返回 `(新增, 合并)`。
    pub fn import_entries(
        &self,
        rows: &[(String, String, i64, Option<String>)],
    ) -> Result<(usize, usize)> {
        let mut added = 0usize;
        let mut merged = 0usize;
        for (password, source, hit_count, last_hit_at) in rows {
            let existing: Option<(i64, Option<String>)> = self
                .conn
                .query_row(
                    "SELECT hit_count, last_hit_at FROM passwords
                     WHERE password = ?1 AND source = ?2",
                    params![password, source],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|e| Error::Config(format!("查询密码库失败: {e}")))?;

            match existing {
                None => {
                    self.conn
                        .execute(
                            "INSERT INTO passwords(password, source, hit_count, created_at, last_hit_at)
                             VALUES(?1, ?2, ?3, ?4, ?5)",
                            params![password, source, hit_count, now_iso(), last_hit_at],
                        )
                        .map_err(|e| Error::Config(format!("写入密码库失败: {e}")))?;
                    added += 1;
                }
                Some((old_hits, old_last)) => {
                    let new_hits = old_hits.max(*hit_count);
                    let new_last = match (&old_last, last_hit_at) {
                        (Some(a), Some(b)) => Some(if b > a { b.clone() } else { a.clone() }),
                        (Some(a), None) => Some(a.clone()),
                        (None, Some(b)) => Some(b.clone()),
                        (None, None) => None,
                    };
                    if new_hits != old_hits || new_last != old_last {
                        self.conn
                            .execute(
                                "UPDATE passwords SET hit_count = ?1, last_hit_at = ?2
                                 WHERE password = ?3 AND source = ?4",
                                params![new_hits, new_last, password, source],
                            )
                            .map_err(|e| Error::Config(format!("更新密码库失败: {e}")))?;
                    }
                    merged += 1;
                }
            }
        }
        Ok((added, merged))
    }

    /// 候选密码：同来源 → 无来源 → 其他来源，段内按命中排序，去重保序
    pub fn candidates_for(&self, source: &str, limit: usize) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT password FROM passwords
                  ORDER BY CASE WHEN source = ?1 THEN 0
                                WHEN source = '' THEN 1
                                ELSE 2 END ASC,
                           hit_count DESC, last_hit_at DESC
                  LIMIT ?2",
            )
            .map_err(|e| Error::Config(format!("查询密码库失败: {e}")))?;
        let rows = stmt
            .query_map(params![source, SCAN_CAP], |row| row.get::<_, String>(0))
            .map_err(|e| Error::Config(format!("查询密码库失败: {e}")))?;
        let mut out: Vec<String> = Vec::new();
        for row in rows.flatten() {
            if !out.iter().any(|p| p == &row) {
                out.push(row);
            }
        }
        if limit > 0 && out.len() > limit {
            out.truncate(limit);
        }
        Ok(out)
    }

    pub fn count(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM passwords", [], |r| r.get(0))
            .map_err(|e| Error::Config(format!("查询密码库失败: {e}")))
    }

    pub fn sources(&self) -> Result<Vec<SourceStat>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT source, COUNT(*) AS c, COALESCE(SUM(hit_count), 0) AS h
                   FROM passwords GROUP BY source ORDER BY c DESC, source ASC",
            )
            .map_err(|e| Error::Config(format!("查询密码库失败: {e}")))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(SourceStat {
                    source: r.get(0)?,
                    count: r.get(1)?,
                    total_hits: r.get(2)?,
                })
            })
            .map_err(|e| Error::Config(format!("查询密码库失败: {e}")))?;
        Ok(rows.flatten().collect())
    }

    pub fn list_all(&self) -> Result<Vec<Entry>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, password, source, hit_count, created_at, last_hit_at
                   FROM passwords ORDER BY source, hit_count DESC",
            )
            .map_err(|e| Error::Config(format!("查询密码库失败: {e}")))?;
        let rows = stmt
            .query_map([], row_to_entry)
            .map_err(|e| Error::Config(format!("查询密码库失败: {e}")))?;
        Ok(rows.flatten().collect())
    }

    /// 统一查询：关键词对 password/source 大小写不敏感包含匹配
    pub fn query(
        &self,
        keyword: &str,
        source: Option<&str>,
        order: &str,
        descending: bool,
        limit: usize,
    ) -> Result<Vec<Entry>> {
        let mut where_parts: Vec<String> = Vec::new();
        let mut params_vec: Vec<String> = Vec::new();

        let kw = keyword.trim().to_lowercase();
        if !kw.is_empty() {
            let esc = kw
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            where_parts.push(
                "(LOWER(password) LIKE ? ESCAPE '\\' OR LOWER(source) LIKE ? ESCAPE '\\')".into(),
            );
            params_vec.push(format!("%{esc}%"));
            params_vec.push(format!("%{esc}%"));
        }
        if let Some(s) = source {
            where_parts.push("source = ?".into());
            params_vec.push(s.to_string());
        }

        let mut sql = String::from(
            "SELECT id, password, source, hit_count, created_at, last_hit_at FROM passwords",
        );
        if !where_parts.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&where_parts.join(" AND "));
        }
        let dir = if descending { "DESC" } else { "ASC" };
        match order {
            "hits" => sql.push_str(&format!(
                " ORDER BY hit_count {dir}, source ASC, id ASC"
            )),
            "recent" => sql.push_str(&format!(
                " ORDER BY (last_hit_at IS NULL) ASC, last_hit_at {dir}, id ASC"
            )),
            "password" => sql.push_str(&format!(" ORDER BY password {dir}, id ASC")),
            _ => sql.push_str(&format!(
                " ORDER BY source {dir}, hit_count DESC, id ASC"
            )),
        }
        if limit > 0 {
            sql.push_str(&format!(" LIMIT {limit}"));
        }

        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| Error::Config(format!("查询密码库失败: {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params_vec.iter()), row_to_entry)
            .map_err(|e| Error::Config(format!("查询密码库失败: {e}")))?;
        Ok(rows.flatten().collect())
    }

    pub fn get(&self, id: i64) -> Result<Option<Entry>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, password, source, hit_count, created_at, last_hit_at
                   FROM passwords WHERE id = ?1",
            )
            .map_err(|e| Error::Config(format!("查询密码库失败: {e}")))?;
        let mut rows = stmt
            .query_map(params![id], row_to_entry)
            .map_err(|e| Error::Config(format!("查询密码库失败: {e}")))?;
        Ok(rows.next().and_then(|r| r.ok()))
    }

    pub fn delete(&self, id: i64) -> Result<bool> {
        let changed = self
            .conn
            .execute("DELETE FROM passwords WHERE id = ?1", params![id])
            .map_err(|e| Error::Config(format!("删除密码失败: {e}")))?;
        Ok(changed > 0)
    }

    pub fn update_password(&self, id: i64, password: &str, source: &str) -> Result<()> {
        self.conn
            .execute(
                "UPDATE passwords SET password = ?2, source = ?3 WHERE id = ?1",
                params![id, password, source],
            )
            .map_err(|e| Error::Config(format!("更新密码失败: {e}")))?;
        Ok(())
    }

    /// 仅测试/调试用：确认表存在
    pub fn has_table(&self) -> Result<bool> {
        let name: Option<String> = self
            .conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='passwords'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| Error::Config(format!("查询失败: {e}")))?;
        Ok(name.is_some())
    }
}

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<Entry> {
    Ok(Entry {
        id: row.get(0)?,
        password: row.get(1)?,
        source: row.get(2)?,
        hit_count: row.get(3)?,
        created_at: row.get(4)?,
        last_hit_at: row.get(5)?,
    })
}

fn now_iso() -> String {
    chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_recall() {
        let v = Vault::open_in_memory().unwrap();
        v.record_success("pw1", "a.com").unwrap();
        v.record_success("pw1", "a.com").unwrap();
        v.record_success("pw2", "").unwrap();
        assert_eq!(v.count().unwrap(), 2);

        // 同来源优先
        let c = v.candidates_for("a.com", 0).unwrap();
        assert_eq!(c, vec!["pw1", "pw2"]);
        // 其他来源时仍能取到（不隔离来源）
        let c = v.candidates_for("b.com", 0).unwrap();
        assert_eq!(c, vec!["pw2", "pw1"]);

        let e = v.list_all().unwrap();
        let pw1 = e.iter().find(|x| x.password == "pw1").unwrap();
        assert_eq!(pw1.hit_count, 2);
    }

    #[test]
    fn query_and_delete() {
        let v = Vault::open_in_memory().unwrap();
        v.add_manual("hello", "x.com").unwrap();
        v.add_manual("world", "").unwrap();
        let got = v.query("HELL", None, "source", false, 0).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].password, "hello");
        assert!(v.delete(got[0].id).unwrap());
        assert_eq!(v.count().unwrap(), 1);
    }
}
