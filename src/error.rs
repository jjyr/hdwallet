pub use crate::ChainPathError;

use rand_core;

#[derive(Debug)]
pub enum Error {
    /// Index is out of range
    KeyIndexOutOfRange,
    /// ChainPathError
    ChainPath(ChainPathError),
    Secp(secp256k1::Error),
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
