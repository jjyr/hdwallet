use hdwallet::secp256k1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    MisChecksum,
    UnknownVersion,
    Secp(secp256k1::Error),
    InvalidBase58,
}

impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Self {
        Error::Secp(err)
    }
}
