use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::error::{CatpError, CatpResult};

/// A long-term agent keypair for DID-bound key exchange.
pub struct AgentKeyPair {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl AgentKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }
}

/// A 32-byte shared session key derived from X25519 key exchange.
#[derive(Debug, Clone)]
pub struct SessionKey(pub [u8; 32]);

/// Perform X25519 key exchange using an ephemeral local secret and a remote public key.
/// Returns the ephemeral public key (to send to the remote) and the shared session key.
pub fn key_exchange(remote_public_bytes: &[u8; 32]) -> CatpResult<(PublicKey, SessionKey)> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let remote_public = PublicKey::from(*remote_public_bytes);
    let shared = ephemeral_secret.diffie_hellman(&remote_public);
    Ok((ephemeral_public, SessionKey(*shared.as_bytes())))
}

/// Perform static X25519 key exchange (agent long-term key with remote public key).
pub fn static_key_exchange(
    keypair: &AgentKeyPair,
    remote_public_bytes: &[u8; 32],
) -> CatpResult<SessionKey> {
    let remote_public = PublicKey::from(*remote_public_bytes);
    let shared = keypair.secret.diffie_hellman(&remote_public);
    Ok(SessionKey(*shared.as_bytes()))
}

/// Encrypt plaintext with AES-256-GCM using the session key.
/// Returns (nonce, ciphertext).
pub fn encrypt(session_key: &SessionKey, plaintext: &[u8]) -> CatpResult<(Vec<u8>, Vec<u8>)> {
    let key = Key::<Aes256Gcm>::from_slice(&session_key.0);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CatpError::Encryption(e.to_string()))?;
    Ok((nonce.to_vec(), ciphertext))
}

/// Decrypt ciphertext with AES-256-GCM using the session key and nonce.
pub fn decrypt(
    session_key: &SessionKey,
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> CatpResult<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(&session_key.0);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CatpError::Decryption(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let session_key = SessionKey([42u8; 32]);
        let plaintext = b"hello, agent world";
        let (nonce, ciphertext) = encrypt(&session_key, plaintext).unwrap();
        let decrypted = decrypt(&session_key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key1 = SessionKey([1u8; 32]);
        let key2 = SessionKey([2u8; 32]);
        let (nonce, ciphertext) = encrypt(&key1, b"secret").unwrap();
        assert!(decrypt(&key2, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn key_exchange_produces_shared_secret() {
        let alice = AgentKeyPair::generate();
        let bob = AgentKeyPair::generate();

        let alice_shared = static_key_exchange(&alice, &bob.public_key_bytes()).unwrap();
        let bob_shared = static_key_exchange(&bob, &alice.public_key_bytes()).unwrap();

        // X25519 DH: alice.secret * bob.public == bob.secret * alice.public
        assert_eq!(alice_shared.0, bob_shared.0);
    }

    #[test]
    fn ephemeral_key_exchange_produces_key() {
        let bob = AgentKeyPair::generate();
        let (ephemeral_pub, _session_key) = key_exchange(&bob.public_key_bytes()).unwrap();
        assert_ne!(ephemeral_pub.to_bytes(), [0u8; 32]);
    }
}
