#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    InvalidKeyIndex,
    InvalidResultKey,
    IndexOutRange,
}
