use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum AegisError {
    #[error("repository path does not exist: {0}")]
    RepositoryNotFound(PathBuf),
    #[error("repository path is not a directory: {0}")]
    RepositoryNotDirectory(PathBuf),
    #[error("I/O failure at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("JSON parse failure at {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

pub type Result<T> = std::result::Result<T, AegisError>;

