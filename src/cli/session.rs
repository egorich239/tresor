use crate::{
    age::RecepientStr,
    api::{ApiError, Nonce, SessionRequestPayload, SessionResponse, SignedMessage, VerifyStatus},
    cli::{ClientError, ClientResult},
    enc::AesSession,
    identity::SigningIdentity,
};
use reqwest::blocking::Client;
use serde::{Serialize, de::DeserializeOwned};
use std::io::Read;

#[derive(Debug)]
pub struct Session<'c> {
    aes_session: AesSession,
    server_url: String,
    client: &'c Client,
}

impl<'c> Session<'c> {
    pub fn query<Q: Serialize, A: DeserializeOwned>(
        &self,
        endpoint: &str,
        request: Q,
    ) -> ClientResult<A> {
        let payload_bytes = serde_json::to_vec(&request).map_err(ClientError::internal)?;
        let ciphertext: Vec<_> = self.aes_session.encrypt(&payload_bytes).into();

        let response = self
            .client
            .post(format!("{}/{}", self.server_url, endpoint))
            .header(
                "X-Tresor-Session-Id",
                self.aes_session.session_id().to_hex(),
            )
            .body(ciphertext)
            .send()?;

        if !response.status().is_success() {
            let err: ApiError = response.json()?;
            return Err(err.into());
        }

        let response = response.bytes()?;
        let response = response
            .as_ref()
            .try_into()
            .map_err(|_| ClientError::MalformedResponse)?;
        let response = self
            .aes_session
            .decrypt(response)
            .ok_or(ClientError::MalformedResponse)?;
        let response =
            serde_json::from_slice(&response).map_err(|_| ClientError::MalformedResponse)?;
        Ok(response)
    }
}

pub fn request_session<'c>(
    client: &'c Client,
    signer: &dyn SigningIdentity,
    server_url: &str,
) -> ClientResult<Session<'c>> {
    let age_identity = age::x25519::Identity::generate();
    let recepient = RecepientStr::new(age_identity.to_public());

    let payload = SessionRequestPayload {
        nonce: Nonce::generate(),
        identity: signer.verifying_identity(),
        recepient,
    };

    let request = SignedMessage::new(payload, signer)?;
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
        aes_session: AesSession::new(
            session_payload.enc_key.clone(),
            session_payload.session_id.clone(),
        ),
        server_url: server_url.to_string(),
        client,
    })
}
