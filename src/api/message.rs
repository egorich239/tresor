use ed25519_dalek::Signature;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha512};

use crate::identity::{SignatureResult, SigningIdentity, VerifyingIdentity};

pub trait Payload: Clone {
    type Bytes: AsRef<[u8]>;

    fn to_bytes(&self) -> Self::Bytes;
}

impl<T: Serialize + Clone> Payload for T {
    type Bytes = Vec<u8>;
    fn to_bytes(&self) -> Self::Bytes {
        serde_json::to_vec(self).unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct MessageSignature(Signature);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedMessage<P: Payload> {
    payload: P,
    signature: MessageSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyStatus {
    Ok,
    Failed,
}

impl<P: Payload> SignedMessage<P> {
    pub fn new(payload: P, identity: &dyn SigningIdentity) -> SignatureResult<Self> {
        let signature = MessageSignature(identity.sign_prehashed(Self::_prehash(&payload))?);
        Ok(Self { payload, signature })
    }

    pub fn verify(&self, identity: &VerifyingIdentity) -> VerifyStatus {
        if identity.verify_prehashed(Self::_prehash(&self.payload), self.signature()) {
            VerifyStatus::Ok
        } else {
            VerifyStatus::Failed
        }
    }

    fn signature(&self) -> &Signature {
        &self.signature.0
    }

    pub fn payload(&self) -> &P {
        &self.payload
    }

    fn _prehash(payload: &P) -> Sha512 {
        let bytes = payload.to_bytes();
        let mut prehashed = Sha512::new();
        prehashed.update(&bytes);
        prehashed
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
