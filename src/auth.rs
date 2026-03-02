use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::protocol::AuthChallengePayload;

type HmacSha256 = Hmac<Sha256>;

const HKDF_SALT: &[u8] = b"pigeon-relay-auth-v1";

#[derive(Debug, Clone)]
pub struct ChallengeRecord {
    pub challenge_id: String,
    pub client_pubkey: [u8; 32],
    pub server_secret: [u8; 32],
    pub nonce: Vec<u8>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid client public key")]
    InvalidClientPublicKey,
    #[error("invalid base64 payload")]
    InvalidBase64,
    #[error("invalid challenge")]
    InvalidChallenge,
    #[error("challenge expired")]
    ChallengeExpired,
    #[error("proof verification failed")]
    InvalidProof,
}

pub fn create_challenge(
    client_pubkey_b64: &str,
    challenge_ttl: Duration,
) -> Result<(AuthChallengePayload, ChallengeRecord), AuthError> {
    let client_pubkey_bytes = STANDARD
        .decode(client_pubkey_b64)
        .map_err(|_| AuthError::InvalidBase64)?;
    if client_pubkey_bytes.len() != 32 {
        return Err(AuthError::InvalidClientPublicKey);
    }

    let mut client_pubkey = [0_u8; 32];
    client_pubkey.copy_from_slice(&client_pubkey_bytes);

    let mut secret_bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut secret_bytes);
    let server_secret = StaticSecret::from(secret_bytes);
    let server_pubkey = PublicKey::from(&server_secret);

    let mut nonce = [0_u8; 16];
    rand::rng().fill_bytes(&mut nonce);

    let now = Utc::now();
    let expires_at =
        now + chrono::Duration::from_std(challenge_ttl).unwrap_or(chrono::Duration::seconds(30));
    let challenge_id = Uuid::new_v4().to_string();

    let payload = AuthChallengePayload {
        challenge_id: challenge_id.clone(),
        server_pubkey_b64: STANDARD.encode(server_pubkey.as_bytes()),
        nonce_b64: STANDARD.encode(nonce),
        issued_at_ms: now.timestamp_millis(),
        expires_at_ms: expires_at.timestamp_millis(),
    };

    let record = ChallengeRecord {
        challenge_id,
        client_pubkey,
        server_secret: secret_bytes,
        nonce: nonce.to_vec(),
        issued_at: now,
        expires_at,
    };

    Ok((payload, record))
}

pub fn verify_proof(record: &ChallengeRecord, proof_b64: &str) -> Result<String, AuthError> {
    if Utc::now() > record.expires_at {
        return Err(AuthError::ChallengeExpired);
    }

    let proof = STANDARD
        .decode(proof_b64)
        .map_err(|_| AuthError::InvalidBase64)?;

    let client_public = PublicKey::from(record.client_pubkey);
    let server_secret = StaticSecret::from(record.server_secret);
    let shared_secret = server_secret.diffie_hellman(&client_public);

    let mut auth_key = [0_u8; 32];
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret.as_bytes());

    let mut info = Vec::with_capacity(
        record.challenge_id.len() + record.nonce.len() + record.client_pubkey.len(),
    );
    info.extend_from_slice(record.challenge_id.as_bytes());
    info.extend_from_slice(&record.nonce);
    info.extend_from_slice(&record.client_pubkey);

    hkdf.expand(&info, &mut auth_key)
        .map_err(|_| AuthError::InvalidChallenge)?;

    let signed_message = proof_message(&record.challenge_id, record.issued_at.timestamp_millis());
    let mut mac = HmacSha256::new_from_slice(&auth_key).map_err(|_| AuthError::InvalidChallenge)?;
    mac.update(&signed_message);
    let expected = mac.finalize().into_bytes();

    if expected.ct_eq(&proof).unwrap_u8() != 1 {
        return Err(AuthError::InvalidProof);
    }

    let identity_hash = Sha256::digest(record.client_pubkey);
    Ok(hex::encode(identity_hash))
}

pub fn proof_message(challenge_id: &str, issued_at_ms: i64) -> Vec<u8> {
    let mut output = Vec::with_capacity(challenge_id.len() + 8);
    output.extend_from_slice(challenge_id.as_bytes());
    output.extend_from_slice(&issued_at_ms.to_be_bytes());
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_generated_proof_succeeds() {
        let mut client_secret_bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut client_secret_bytes);
        let client_secret = StaticSecret::from(client_secret_bytes);
        let client_public = PublicKey::from(&client_secret);

        let (challenge_payload, challenge_record) = create_challenge(
            &STANDARD.encode(client_public.as_bytes()),
            Duration::from_secs(30),
        )
        .expect("challenge should be created");

        let proof = build_proof(&challenge_record);
        let identity_hash = verify_proof(&challenge_record, &proof).expect("proof should verify");

        assert_eq!(identity_hash.len(), 64);
        assert_eq!(
            challenge_payload.challenge_id,
            challenge_record.challenge_id
        );
    }

    #[test]
    fn tampered_proof_fails() {
        let mut client_secret_bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut client_secret_bytes);
        let client_secret = StaticSecret::from(client_secret_bytes);
        let client_public = PublicKey::from(&client_secret);

        let (_, challenge_record) = create_challenge(
            &STANDARD.encode(client_public.as_bytes()),
            Duration::from_secs(30),
        )
        .expect("challenge should be created");

        let mut proof_bytes = STANDARD
            .decode(build_proof(&challenge_record))
            .expect("proof should decode");
        proof_bytes[0] ^= 0xFF;
        let tampered = STANDARD.encode(proof_bytes);

        let result = verify_proof(&challenge_record, &tampered);
        assert!(matches!(result, Err(AuthError::InvalidProof)));
    }

    fn build_proof(record: &ChallengeRecord) -> String {
        let client_public = PublicKey::from(record.client_pubkey);
        let server_secret = StaticSecret::from(record.server_secret);
        let shared_secret = server_secret.diffie_hellman(&client_public);

        let mut key = [0_u8; 32];
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret.as_bytes());
        let mut info = Vec::with_capacity(
            record.challenge_id.len() + record.nonce.len() + record.client_pubkey.len(),
        );
        info.extend_from_slice(record.challenge_id.as_bytes());
        info.extend_from_slice(&record.nonce);
        info.extend_from_slice(&record.client_pubkey);
        hkdf.expand(&info, &mut key)
            .expect("hkdf should derive auth key");

        let signed_message =
            proof_message(&record.challenge_id, record.issued_at.timestamp_millis());
        let mut mac = HmacSha256::new_from_slice(&key).expect("hmac init should work");
        mac.update(&signed_message);
        STANDARD.encode(mac.finalize().into_bytes())
    }
}
