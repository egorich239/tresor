use age::{Encryptor, x25519::Recipient};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::Write;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct RecepientStr(Recipient);

impl RecepientStr {
    pub fn new(recipient: Recipient) -> Self {
        Self(recipient)
    }

    pub fn recepient(&self) -> &Recipient {
        &self.0
    }

    /// Encrypts a payload using the recepient.
    ///
    /// NOTE: As far as I can tell given a valid single recepient, we don't
    /// expect any runtime failures.
    pub fn encrypt(&self, payload: &[u8]) -> Vec<u8> {
        let recepient: Box<dyn age::Recipient> = Box::new(self.0.clone());
        let recepients = vec![recepient.as_ref()];
        let encryptor = Encryptor::with_recipients(recepients.into_iter()).unwrap();

        let mut encrypted = vec![];
        let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
        writer.write_all(payload.as_ref()).unwrap();
        writer.finish().unwrap();

        encrypted
    }
}

impl From<Recipient> for RecepientStr {
    fn from(recipient: Recipient) -> Self {
        Self(recipient)
    }
}

impl Serialize for RecepientStr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for RecepientStr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self(
            Recipient::from_str(&s).map_err(serde::de::Error::custom)?,
        ))
    }
}
