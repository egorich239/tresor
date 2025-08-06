use crate::api::error::ApiResult;
use crate::api::session::SessionEncKey;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use sha2::digest::consts::U12;

pub fn encrypt(cleartext: &[u8], key: &SessionEncKey) -> ApiResult<(Vec<u8>, Nonce<U12>)> {
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).unwrap();

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, cleartext).unwrap();

    Ok((ciphertext, *nonce))
}

pub fn decrypt(ciphertext: &[u8], nonce: &Nonce<U12>, key: &SessionEncKey) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).unwrap();
    cipher.decrypt(nonce, ciphertext).ok()
}
