pub trait Serialize<T> {
    fn serialize(&self) -> T;
}

pub trait Deserialize<T> {
    fn deserialize(&self) -> T;
}
