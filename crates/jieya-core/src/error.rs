use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("{0}")]
    SevenZip(String),

    #[error("已取消")]
    Cancelled,

    #[error("探测失败: {0}")]
    Probe(String),

    #[error("{0}")]
    Config(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
