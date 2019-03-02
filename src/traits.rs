pub trait Serialize<T> {
    fn serialize(&self) -> T;
}

pub trait Deserialize<T, E>: Sized {
    fn deserialize(t: T) -> Result<Self, E>;
}
