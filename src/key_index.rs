use crate::error::Error;

const HARDENDED_KEY_START_INDEX: u64 = 2_147_483_648; // 2 ** 31
const HARDENDED_KEY_END_INDEX: u64 = 4_294_967_295; // 2 ** 32 - 1

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KeyIndex {
    Normal(u64),
    Hardened(u64),
}

impl KeyIndex {
    pub fn raw_index(&self) -> u64 {
        match self {
            KeyIndex::Normal(i) => *i,
            KeyIndex::Hardened(i) => *i,
        }
    }

    pub fn normalize_index(&self) -> u64 {
        match self {
            KeyIndex::Normal(i) => *i,
            KeyIndex::Hardened(i) => *i - HARDENDED_KEY_START_INDEX,
        }
    }

    pub fn is_valid(&self) -> bool {
        match self {
            KeyIndex::Normal(i) => *i < HARDENDED_KEY_START_INDEX,
            KeyIndex::Hardened(i) => {
                *i >= HARDENDED_KEY_START_INDEX && *i <= HARDENDED_KEY_END_INDEX
            }
        }
    }

    pub fn hardened_from_normalize_index(i: u64) -> Result<KeyIndex, Error> {
        if i < HARDENDED_KEY_START_INDEX {
            Ok(KeyIndex::Hardened(HARDENDED_KEY_START_INDEX + i))
        } else if i <= HARDENDED_KEY_END_INDEX {
            Ok(KeyIndex::Hardened(i))
        } else {
            Err(Error::IndexOutRange)
        }
    }

    pub fn from_index(i: u64) -> Result<Self, Error> {
        if i < HARDENDED_KEY_START_INDEX {
            Ok(KeyIndex::Normal(i))
        } else if i <= HARDENDED_KEY_END_INDEX {
            Ok(KeyIndex::Hardened(i))
        } else {
            Err(Error::IndexOutRange)
        }
    }
}

impl From<u64> for KeyIndex {
    fn from(index: u64) -> Self {
        KeyIndex::from_index(index).expect("KeyIndex")
    }
}
