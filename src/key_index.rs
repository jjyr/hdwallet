use crate::error::Error;

const HARDENED_KEY_START_INDEX: u32 = 2_147_483_648; // 2 ** 31

/// KeyIndex indicates the key type and index of a child key.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KeyIndex {
    /// Normal key, index range is from 0 to 2 ** 31 - 1
    Normal(u32),
    /// Hardened key, index range is from 2 ** 31 to 2 ** 32 - 1
    Hardened(u32),
}

impl KeyIndex {
    /// Return raw index value
    pub fn raw_index(self) -> u32 {
        match self {
            KeyIndex::Normal(i) => i,
            KeyIndex::Hardened(i) => i,
        }
    }

    /// Return normalize index, it will return index subtract 2 ** 31 for hardended key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # extern crate hdwallet;
    /// use hdwallet::KeyIndex;
    ///
    /// assert_eq!(KeyIndex::Normal(0).normalize_index(), 0);
    /// assert_eq!(KeyIndex::Hardened(2_147_483_648).normalize_index(), 0);
    /// ```
    pub fn normalize_index(self) -> u32 {
        match self {
            KeyIndex::Normal(i) => i,
            KeyIndex::Hardened(i) => i - HARDENED_KEY_START_INDEX,
        }
    }

    /// Check index range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # extern crate hdwallet;
    /// use hdwallet::KeyIndex;
    ///
    /// assert!(KeyIndex::Normal(0).is_valid());
    /// assert!(!KeyIndex::Normal(2_147_483_648).is_valid());
    /// assert!(KeyIndex::Hardened(2_147_483_648).is_valid());
    /// ```
    pub fn is_valid(self) -> bool {
        match self {
            KeyIndex::Normal(i) => i < HARDENED_KEY_START_INDEX,
            KeyIndex::Hardened(i) => i >= HARDENED_KEY_START_INDEX,
        }
    }

    /// Generate Hardened KeyIndex from normalize index value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # extern crate hdwallet;
    /// use hdwallet::KeyIndex;
    ///
    /// // hardended key from zero
    /// let hardened_index_zero = KeyIndex::hardened_from_normalize_index(0).unwrap();
    /// assert_eq!(hardened_index_zero, KeyIndex::Hardened(2_147_483_648));
    /// // also allow raw index for convernient
    /// let hardened_index_zero = KeyIndex::hardened_from_normalize_index(2_147_483_648).unwrap();
    /// assert_eq!(hardened_index_zero, KeyIndex::Hardened(2_147_483_648));
    /// ```
    pub fn hardened_from_normalize_index(i: u32) -> Result<KeyIndex, Error> {
        if i < HARDENED_KEY_START_INDEX {
            Ok(KeyIndex::Hardened(HARDENED_KEY_START_INDEX + i))
        } else {
            Ok(KeyIndex::Hardened(i))
        }
    }

    /// Generate KeyIndex from raw index value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # extern crate hdwallet;
    /// use hdwallet::KeyIndex;
    ///
    /// let normal_key = KeyIndex::from_index(0).unwrap();
    /// assert_eq!(normal_key, KeyIndex::Normal(0));
    /// let hardened_key = KeyIndex::from_index(2_147_483_648).unwrap();
    /// assert_eq!(hardened_key, KeyIndex::Hardened(2_147_483_648));
    /// ```
    pub fn from_index(i: u32) -> Result<Self, Error> {
        if i < HARDENED_KEY_START_INDEX {
            Ok(KeyIndex::Normal(i))
        } else {
            Ok(KeyIndex::Hardened(i))
        }
    }
}

impl From<u32> for KeyIndex {
    fn from(index: u32) -> Self {
        KeyIndex::from_index(index).expect("KeyIndex")
    }
}
