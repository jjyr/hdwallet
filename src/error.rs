#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// Use a wrong KeyIndex
    InvalidKeyIndex,
    /// Index is out of range according to key index type.
    IndexOutRange,
    /// Key is invalid, should try next index.
    InvalidResultKey,
}
