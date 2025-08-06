use std::fmt;

use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RandomBytes<const N: usize>([u8; N]);

impl<const N: usize> RandomBytes<N> {
    pub fn generate() -> Self {
        // It so happens that rust only kinda has usize template params.
        // Neither r#gen nor fill work for arbitrary sizes, because they are
        // each individual array size requires a separate trait impl. Really?
        let mut rng = rand::thread_rng();
        let mut bytes: [u8; N] = [0; N];
        for e in bytes.iter_mut() {
            *e = rng.r#gen();
        }
        Self(bytes)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> fmt::Debug for RandomBytes<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RandomBytes({})", self.to_hex())
    }
}

impl<const N: usize> TryFrom<&str> for RandomBytes<N> {
    type Error = hex::FromHexError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value)?;
        Ok(Self(
            bytes
                .try_into()
                .map_err(|_| hex::FromHexError::InvalidStringLength)?,
        ))
    }
}

impl<const N: usize> Serialize for RandomBytes<N> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de, const N: usize> Deserialize<'de> for RandomBytes<N> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        s.as_str().try_into().map_err(serde::de::Error::custom)
    }
}
