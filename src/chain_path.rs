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

pub enum ChainPath {
    Root,
    Node(Box<ChainPath>, KeyIndex),
}

impl ChainPath {
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
                    sub_path[..sub_path.len() - 2].parse::<u64>()
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

    pub fn to_string(&self) -> String {
        unimplemented!()
    }
}

impl From<String> for ChainPath {
    fn from(path: String) -> Self {
        ChainPath::from_string(path).expect("into chain path")
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
