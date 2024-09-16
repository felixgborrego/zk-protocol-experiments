use derive_more::derive::Display;
use derive_more::From;

pub type Result<T> = core::result::Result<T, Error>;
#[derive(Debug, From, Display)]
pub enum Error {
    Token(String),
    #[from]
    IO(std::io::Error),
    #[from]
    Decode(base64::DecodeError),
    #[from]
    ZK(bellman::VerificationError),
}

impl std::error::Error for Error {}
