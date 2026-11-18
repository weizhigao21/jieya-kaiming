//! 解压开镜引擎
//!
//! 模块划分与 Python 版一一对应，见 docs/重写方案.md：
//! - [`config`]   <- core/config.py
//! - [`sevenzip`] <- core/sevenzip.py
//! - [`detect`]   <- core/archive_detect.py
//! - [`probe`]    <- core/probe.py
//! - [`output`]   <- core/output_plan.py
//! - [`pipeline`] <- core/pipeline.py
//! - [`walk`]     <- core/filewalk.py
//! - [`name_repair`] <- core/name_repair.py
//! - [`zip_dir`]  <- ZIP 中央目录公共解析（zip_crypto / name_repair 共用）

pub mod bundle;
pub mod cleanup;
pub mod config;
pub mod detect;
pub mod embedded;
pub mod error;
pub mod fmt;
pub mod models;
pub mod name_repair;
pub mod output;
pub mod password;
pub mod pipeline;
pub mod probe;
pub mod sevenzip;
pub mod store;
pub mod vault;
pub mod vault_io;
pub mod walk;
pub mod zip_crypto;
pub mod zip_dir;

pub use cleanup::Leftover;
pub use config::Config;
pub use embedded::EmbeddedZip;
pub use error::{Error, Result};
pub use name_repair::{repair_tree, NameRepair};
pub use pipeline::{Event, Pipeline, RunReport};
pub use sevenzip::SevenZip;
pub use store::{StoredTask, TaskStore};
pub use vault::Vault;
pub use vault_io::{export_vault, import_vault, ExportResult, ImportResult};
pub use zip_crypto::{AesEntry, ZipFilter};
