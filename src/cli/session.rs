use crate::{
    age::RecepientStr,
    api::{
        message::{SignedMessage, VerifyStatus},
        session::{Nonce, SessionEncKey, SessionId, SessionRequestPayload, SessionResponse},
    },
    identity::{SignatureError, SigningIdentity, SoftwareIdentity},
};
use reqwest::blocking::Client;
use std::io::{self, Read};

pub struct Session {
    id: SessionId,
    enc_key: SessionEncKey, // Placeholder for the actual symmetric key type
}

pub fn request_session<S: SigningIdentity>(
    client: &Client,
    signer: &S,
    server_url: &str,
) -> io::Result<Session> {
    // 1. Generate an ephemeral age identity
    let age_identity = age::x25519::Identity::generate();
    let recepient = RecepientStr::new(age_identity.to_public());

    // 2. Construct the request payload
    let payload = SessionRequestPayload {
        nonce: Nonce::new(),
        identity: signer.verifying_identity(),
        recepient,
    };

    // 3. Sign the payload to create the request message
    let request =
        SignedMessage::new(payload, signer).map_err(|e| io::Error::other(e.to_string()))?;

    // 4. Send the request to the server
    let response = client
        .post(format!("{}/session", server_url))
        .json(&request)
        .send()
        .map_err(|e| io::Error::other(e.to_string()))?;

    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "server returned error: {}",
            response.status()
        )));
    }

    let response_bytes = response
        .bytes()
        .map_err(|e| io::Error::other(e.to_string()))?
        .to_vec();

    // 5. Decrypt the response with the ephemeral age key
    let decryptor = age::Decryptor::new(&response_bytes[..]).map_err(io::Error::other)?;
    let mut decrypted = vec![];
    let mut reader = decryptor
        .decrypt(std::iter::once(&age_identity as &dyn age::Identity))
        .map_err(io::Error::other)?;
    reader.read_to_end(&mut decrypted)?;
    let decrypted_response: SessionResponse =
        serde_json::from_slice(&decrypted).map_err(io::Error::other)?;

    // 6. Verify the server's signature on the response
    let server_identity = decrypted_response.payload().certificate.identity();
    if decrypted_response.verify(server_identity) != VerifyStatus::Ok {
        return Err(io::Error::other("invalid server signature"));
    }

    // 7. Return the session details
    let session_payload = decrypted_response.payload();
    Ok(Session {
        id: session_payload.session_id.clone(),
        enc_key: session_payload.enc_key.clone(),
    })
}
