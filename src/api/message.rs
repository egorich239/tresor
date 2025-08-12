use std::fmt::Debug;

use ed25519_dalek::Signature;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::identity::{SignatureError, SignatureResult, SigningIdentity, VerifyingIdentity};

#[derive(Debug, Clone)]
pub struct MessageSignature(Signature);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedMessage<P: Serialize + Clone + Debug> {
    payload: P,
    signature: MessageSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyStatus {
    Ok,
    Failed,
}

impl<P: Serialize + Clone + Debug> SignedMessage<P> {
    pub fn new(payload: P, identity: &dyn SigningIdentity) -> SignatureResult<Self> {
        let bytes = Self::_bytes(&payload)?;
        let signature = MessageSignature(identity.sign(&bytes)?);
        Ok(Self { payload, signature })
    }

    pub fn verify(&self, identity: &VerifyingIdentity) -> VerifyStatus {
        let Ok(bytes) = Self::_bytes(&self.payload) else {
            return VerifyStatus::Failed;
        };
        match identity.verify(&bytes, self.signature()) {
            true => VerifyStatus::Ok,
            false => VerifyStatus::Failed,
        }
    }

    fn signature(&self) -> &Signature {
        &self.signature.0
    }

    pub fn payload(&self) -> &P {
        &self.payload
    }

    fn _bytes(payload: &P) -> SignatureResult<Vec<u8>> {
        serde_json::to_vec(payload).map_err(SignatureError::new)
    }
}

impl Serialize for MessageSignature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0.to_bytes()))
    }
}

impl<'de> Deserialize<'de> for MessageSignature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let sig_bytes = &bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid key length"))?;
        Ok(MessageSignature(Signature::from_bytes(sig_bytes)))
    }
}
