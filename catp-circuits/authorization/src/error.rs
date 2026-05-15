use thiserror::Error;

#[derive(Debug, Error)]
pub enum CatpError {
    #[error("serialization error: {0}")]
    Serialization(String),
}

pub type CatpResult<T> = Result<T, CatpError>;
