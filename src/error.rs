pub use crate::ChainPathError;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
    /// Index is out of range
    KeyIndexOutOfRange,
    /// ChainPathError
    ChainPath(ChainPathError),
    Secp(secp256k1::Error),
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
