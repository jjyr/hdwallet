use crate::KeyIndex;
use std::fmt;

const MASTER_SYMBOL: &str = "m";
const HARDENED_SYMBOLS: [&str; 2] = ["H", "'"];
const SEPARATOR: char = '/';

#[derive(Clone, Debug)]
pub struct PathError {
    level: usize,
    reason: String,
}

/// ChainPath is used to describe BIP-32 KeyChain path.
///
/// # Examples
///
/// ``` rust
/// # extern crate hdwallet;
/// use hdwallet::{ChainPath, KeyIndex};
///
/// let chain_path = ChainPath::Node(
///     Box::new(ChainPath::Node(
///         Box::new(ChainPath::Root),
///         KeyIndex::hardened_from_normalize_index(1).unwrap()
///     )),
///     KeyIndex::Normal(1)
/// );
/// assert_eq!(chain_path.to_string(), "m/2147483649H/1");
/// assert_eq!(ChainPath::from("m/2147483649H/1"), chain_path);
/// ```
#[derive(Debug, PartialEq, Eq)]
pub enum ChainPath {
    Root,
    Node(Box<ChainPath>, KeyIndex),
}

impl ChainPath {
    /// Convert string represent chain path to ChainPath
    pub fn from_string(path: String) -> Result<ChainPath, PathError> {
        let mut iter = path.split_terminator(SEPARATOR);
        if iter.next() != Some(MASTER_SYMBOL) {
            return Err(PathError {
                level: 0,
                reason: "Must start with 'm'".into(),
            });
        }
        let mut chain_path = ChainPath::Root;
        for (i, sub_path) in iter.enumerate() {
            let level = i + 1;
            let last_char = match sub_path.get((sub_path.len() - 1)..) {
                Some(c) => c,
                None => {
                    return Err(PathError {
                        level,
                        reason: "Subpath can't be blank".into(),
                    })
                }
            };
            let is_hardened = HARDENED_SYMBOLS.contains(&last_char);
            let key_index = {
                let index_result = if is_hardened {
                    sub_path[..sub_path.len() - 1].parse::<u64>()
                } else {
                    sub_path[..].parse::<u64>()
                };
                let index = match index_result {
                    Ok(index) => index,
                    Err(_) => {
                        return Err(PathError {
                            level,
                            reason: "Illegal key index format".into(),
                        })
                    }
                };
                match KeyIndex::from_index(index) {
                    Ok(key_index) => key_index,
                    Err(_) => {
                        return Err(PathError {
                            level,
                            reason: "Key index out of range".into(),
                        })
                    }
                }
            };
            chain_path = ChainPath::Node(Box::new(chain_path), key_index);
        }
        Ok(chain_path)
    }

    /// Convert ChainPath to string represent format
    pub fn to_string(&self) -> String {
        let mut path = self;
        let mut path_levels: Vec<String> = Vec::new();
        loop {
            match path {
                ChainPath::Root => {
                    path_levels.push("m".into());
                    break;
                }
                ChainPath::Node(parent_path, key_index) => {
                    let s = match key_index {
                        KeyIndex::Normal(i) => i.to_string(),
                        KeyIndex::Hardened(i) => format!("{}H", i),
                    };
                    path_levels.push(s);
                    path = parent_path;
                }
            }
        }
        path_levels.reverse();
        path_levels.join("/")
    }
}

impl From<String> for ChainPath {
    fn from(path: String) -> Self {
        ChainPath::from_string(path).expect("into chain path")
    }
}

impl From<&str> for ChainPath {
    fn from(path: &str) -> Self {
        ChainPath::from_string(path.into()).expect("into chain path")
    }
}

impl Into<String> for ChainPath {
    fn into(self) -> String {
        self.to_string()
    }
}

impl fmt::Display for ChainPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_chain_path() {
        assert_eq!(ChainPath::Root.to_string(), "m");
        assert_eq!(
            ChainPath::Node(Box::new(ChainPath::Root), KeyIndex::Normal(1)).to_string(),
            "m/1"
        );
        assert_eq!(
            ChainPath::Node(
                Box::new(ChainPath::Node(
                    Box::new(ChainPath::Root),
                    KeyIndex::hardened_from_normalize_index(1).unwrap()
                )),
                KeyIndex::Normal(1)
            )
            .to_string(),
            "m/2147483649H/1"
        );
    }

    #[test]
    fn test_chain_path_from_string() {
        assert_eq!(ChainPath::from("m"), ChainPath::Root);
        assert_eq!(
            ChainPath::from("m/1"),
            ChainPath::Node(Box::new(ChainPath::Root), KeyIndex::Normal(1))
        );
        assert_eq!(
            ChainPath::from("m/2147483649H/1"),
            ChainPath::Node(
                Box::new(ChainPath::Node(
                    Box::new(ChainPath::Root),
                    KeyIndex::hardened_from_normalize_index(1).unwrap()
                )),
                KeyIndex::Normal(1)
            )
        );
        // alternative hardened key represent
        assert_eq!(
            ChainPath::from("m/2147483649'/1"),
            ChainPath::Node(
                Box::new(ChainPath::Node(
                    Box::new(ChainPath::Root),
                    KeyIndex::hardened_from_normalize_index(1).unwrap()
                )),
                KeyIndex::Normal(1)
            )
        );
        // from invalid string
        assert!(ChainPath::from_string("m/2147483649h/1".into()).is_err());
        assert!(ChainPath::from_string("/2147483649H/1".into()).is_err());
        assert!(ChainPath::from_string("2147483649H/1".into()).is_err());
        assert!(ChainPath::from_string("a".into()).is_err());
    }
}
