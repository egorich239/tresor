use crate::{
    age::RecepientStr,
    identity::{ServerCertificate, SignedMessage, VerifyingKeyHex},
};
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub type SessionRequest = SignedMessage<SessionRequestPayload>;

#[derive(Clone)]
pub struct RandomBytes<const N: usize>([u8; N]);

impl<const N: usize> Default for RandomBytes<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RandomBytes<N> {
    pub fn new() -> Self {
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
}

#[derive(Clone)]
pub struct SessionEncKey(RandomBytes<32>);

pub type Nonce = RandomBytes<16>;
pub type SessionId = RandomBytes<16>;

#[derive(Serialize, Deserialize, Clone)]
pub struct SessionRequestPayload {
    pub nonce: Nonce,
    pub identity: VerifyingKeyHex,
    pub recepient: RecepientStr,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SessionResponsePayload {
    pub nonce: Nonce,
    pub session_id: SessionId,
    pub certificate: ServerCertificate,
    pub enc_key: SessionEncKey,
}

pub type SessionResponse = SignedMessage<SessionResponsePayload>;

impl SessionEncKey {
    pub fn generate() -> Self {
        Self(RandomBytes::new())
    }
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl<const N: usize> Serialize for RandomBytes<N> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for RandomBytes<N> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let bytes_array = &bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid key length"))?;
        Ok(Self(*bytes_array))
    }
}

impl Serialize for SessionEncKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SessionEncKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(RandomBytes::deserialize(deserializer)?))
    }
}
