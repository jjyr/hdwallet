pub use crate::ChainPathError;

use rand_core;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Key index out of range")]
    KeyIndexOutOfRange,
    #[error("Chain path {0}")]
    ChainPath(ChainPathError),
    #[error("Secp256k1 error {0}")]
    Secp(secp256k1::Error),
    #[error("rand error {0}")]
    Rng(rand_core::Error),
}

impl From<ChainPathError> for Error {
    fn from(err: ChainPathError) -> Error {
        Error::ChainPath(err)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Error {
        Error::Secp(err)
    }
}

impl From<rand_core::Error> for Error {
    fn from(err: rand_core::Error) -> Self {
        Error::Rng(err)
    }
}
