use crate::api::SessionEncKey;
use crate::api::SessionId;
use aes_gcm::aead::Payload;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde::de::Error;
use sha2::digest::consts::U12;

#[derive(Debug)]
pub struct AesSession {
    enc_key: SessionEncKey,
    session_id: SessionId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AesNonce(Nonce<U12>);
pub struct AesCiphertextSend(Vec<u8>);

impl AesCiphertextSend {
    pub fn nonce(&self) -> AesNonce {
        AesNonce(*Nonce::from_slice(&self.0[..12]))
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.0[12..]
    }
}

#[derive(Debug)]
pub struct AesCiphertextRecv<'n, 'c> {
    nonce: &'n [u8],
    ciphertext: &'c [u8],
}

impl AesSession {
    pub fn new(enc_key: SessionEncKey, session_id: SessionId) -> Self {
        Self {
            enc_key,
            session_id,
        }
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn encrypt(&self, cleartext: &[u8]) -> AesCiphertextSend {
        let cipher = Aes256Gcm::new_from_slice(self.enc_key.as_slice()).unwrap();

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: cleartext,
                    aad: self.session_id.as_slice(),
                },
            )
            .unwrap();

        let mut full_text = Vec::new();
        full_text.extend_from_slice(nonce);
        full_text.extend_from_slice(&ciphertext);
        AesCiphertextSend(full_text)
    }

    pub fn decrypt(&self, ciphertext: AesCiphertextRecv) -> Option<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(self.enc_key.as_slice()).unwrap();
        let nonce = Nonce::from_slice(ciphertext.nonce);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext.ciphertext,
                    aad: self.session_id.as_slice(),
                },
            )
            .ok()
    }
}

impl From<AesCiphertextSend> for Vec<u8> {
    fn from(ciphertext: AesCiphertextSend) -> Self {
        ciphertext.0
    }
}

impl<'n, 'c> AesCiphertextRecv<'n, 'c> {
    pub fn nonce(&self) -> AesNonce {
        AesNonce(*Nonce::from_slice(self.nonce))
    }
}

impl<'c> TryFrom<&'c [u8]> for AesCiphertextRecv<'c, 'c> {
    type Error = ();

    fn try_from(value: &'c [u8]) -> Result<Self, Self::Error> {
        if value.len() < 12 {
            return Err(());
        }
        Ok(AesCiphertextRecv {
            nonce: &value[..12],
            ciphertext: &value[12..],
        })
    }
}

impl<'n, 'c> From<(&'n AesNonce, &'c [u8])> for AesCiphertextRecv<'n, 'c> {
    fn from(value: (&'n AesNonce, &'c [u8])) -> Self {
        Self {
            nonce: value.0.0.as_slice(),
            ciphertext: value.1,
        }
    }
}

impl AesNonce {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.as_slice())
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        if bytes.len() != 12 {
            return None;
        }
        Some(AesNonce(*Nonce::from_slice(&bytes)))
    }
}

impl Serialize for AesNonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for AesNonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        AesNonce::from_hex(&s).ok_or_else(|| Error::custom("invalid nonce"))
    }
}
