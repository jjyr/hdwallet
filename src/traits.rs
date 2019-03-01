pub trait Serialize<T> {
    fn serialize(&self) -> T;
}

pub trait Deserialize<T, E> {
    fn deserialize(&self) -> Result<T, E>;
}
