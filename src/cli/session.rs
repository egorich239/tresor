use crate::{
    age::RecepientStr,
    api::{
        error::ApiError,
        message::{SignedMessage, VerifyStatus},
        session::{Nonce, SessionEncKey, SessionId, SessionRequestPayload, SessionResponse},
    },
    cli::{ClientError, ClientResult},
    identity::SigningIdentity,
};
use reqwest::blocking::Client;
use std::io::Read;

#[derive(Debug)]
pub struct Session {
    id: SessionId,
    enc_key: SessionEncKey, // Placeholder for the actual symmetric key type
}

pub fn request_session(
    client: &Client,
    signer: &dyn SigningIdentity,
    server_url: &str,
) -> ClientResult<Session> {
    // 1. Generate an ephemeral age identity
    let age_identity = age::x25519::Identity::generate();
    let recepient = RecepientStr::new(age_identity.to_public());

    // 2. Construct the request payload
    let payload = SessionRequestPayload {
        nonce: Nonce::generate(),
        identity: signer.verifying_identity(),
        recepient,
    };

    // 3. Sign the payload to create the request message
    let request = SignedMessage::new(payload, signer)?;

    // 4. Send the request to the server
    let response = client
        .post(format!("{server_url}/session"))
        .json(&request)
        .send()?;

    if !response.status().is_success() {
        let err: ApiError = response.json()?;
        return Err(ClientError::ApiError(err));
    }

    let response = response.bytes()?;

    // 5. Decrypt the response with the ephemeral age key
    let decryptor =
        age::Decryptor::new(&response[..]).map_err(|_| ClientError::MalformedResponse)?;
    let mut decrypted = vec![];
    let mut reader = decryptor
        .decrypt(std::iter::once(&age_identity as &dyn age::Identity))
        .map_err(|_| ClientError::MalformedResponse)?;
    reader
        .read_to_end(&mut decrypted)
        .map_err(|_| ClientError::MalformedResponse)?;
    let response: SessionResponse =
        serde_json::from_slice(&decrypted).map_err(|_| ClientError::MalformedResponse)?;

    // 6. Verify the server's signature on the response
    let server_identity = response.payload().certificate.identity();
    if response.verify(server_identity) != VerifyStatus::Ok {
        return Err(ClientError::InvalidServerSignature);
    }

    // 7. Return the session details
    let session_payload = response.payload();
    Ok(Session {
        id: session_payload.session_id.clone(),
        enc_key: session_payload.enc_key.clone(),
    })
}
