use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::ZeroizeOnDrop;

use crate::error::{CatpError, CatpResult};

const CATP_HKDF_INFO: &[u8] = b"catp-v1-session-key";

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

/// A 32-byte shared session key derived from X25519 + HKDF-SHA256.
/// Key material is zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct SessionKey(pub [u8; 32]);

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionKey([REDACTED])")
    }
}

/// Derive a session key from a raw X25519 DH output using HKDF-SHA256.
/// `context` binds the key to the session parties (include public keys).
fn derive_session_key(dh_output: &[u8; 32], context: &[u8]) -> SessionKey {
    let hk = Hkdf::<Sha256>::new(None, dh_output);
    let mut okm = [0u8; 32];
    hk.expand(context, &mut okm).expect("32 bytes always fits HKDF output");
    SessionKey(okm)
}

/// Perform X25519 ephemeral key exchange with a remote public key.
///
/// Returns `(ephemeral_public_key, session_key)`.
/// The ephemeral public key MUST be sent to the remote peer.
/// The session key is unique to this session — a fresh ephemeral secret is used.
/// The ephemeral public key is bound into the session key derivation to prevent UKS attacks.
pub fn key_exchange(remote_public_bytes: &[u8; 32]) -> CatpResult<(PublicKey, SessionKey)> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let remote_public = PublicKey::from(*remote_public_bytes);
    let shared = ephemeral_secret.diffie_hellman(&remote_public);

    // Bind both public keys into the HKDF context to prevent unknown-key-share attacks.
    let mut context = Vec::with_capacity(64 + CATP_HKDF_INFO.len());
    context.extend_from_slice(ephemeral_public.as_bytes());
    context.extend_from_slice(remote_public_bytes);
    context.extend_from_slice(CATP_HKDF_INFO);

    let session_key = derive_session_key(shared.as_bytes(), &context);
    Ok((ephemeral_public, session_key))
}

/// Perform X25519 static key exchange (agent long-term key with remote public key).
///
/// WARNING: The derived key is deterministic for a fixed keypair.
/// This provides NO forward secrecy — compromise of either long-term key exposes all
/// past sessions. Use only for initial handshake or key agreement, then switch to
/// ephemeral keys. Never use the returned SessionKey to encrypt more than one message.
pub fn static_key_exchange(
    keypair: &AgentKeyPair,
    remote_public_bytes: &[u8; 32],
) -> CatpResult<SessionKey> {
    let remote_public = PublicKey::from(*remote_public_bytes);
    let shared = keypair.secret.diffie_hellman(&remote_public);

    // Bind both parties' static public keys in a canonical (sorted) order so that
    // both sides derive the same key regardless of who initiates the exchange.
    let local_bytes = keypair.public_key_bytes();
    let (first, second) = if local_bytes.as_ref() <= remote_public_bytes.as_ref() {
        (local_bytes.as_ref(), remote_public_bytes.as_ref())
    } else {
        (remote_public_bytes.as_ref(), local_bytes.as_ref())
    };
    let mut context = Vec::with_capacity(64 + CATP_HKDF_INFO.len());
    context.extend_from_slice(first);
    context.extend_from_slice(second);
    context.extend_from_slice(CATP_HKDF_INFO);

    Ok(derive_session_key(shared.as_bytes(), &context))
}

/// Encrypt plaintext with AES-256-GCM using the session key.
///
/// Returns `(nonce, ciphertext)`. The nonce is 12 bytes and must be stored alongside
/// the ciphertext for decryption. Never reuse a session key across multiple messages —
/// derive a fresh key per message or use a proper ratchet scheme.
pub fn encrypt(session_key: &SessionKey, plaintext: &[u8]) -> CatpResult<(Vec<u8>, Vec<u8>)> {
    let key = Key::<Aes256Gcm>::from_slice(&session_key.0);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CatpError::Encryption(e.to_string()))?;
    Ok((nonce.to_vec(), ciphertext))
}

/// Decrypt ciphertext with AES-256-GCM.
///
/// `nonce_bytes` must be exactly 12 bytes (the nonce returned by `encrypt`).
/// Returns `Err` (never panics) on invalid nonce length, wrong key, or tampered ciphertext.
pub fn decrypt(session_key: &SessionKey, nonce_bytes: &[u8], ciphertext: &[u8]) -> CatpResult<Vec<u8>> {
    if nonce_bytes.len() != 12 {
        return Err(CatpError::Decryption(format!(
            "invalid nonce length: expected 12, got {}",
            nonce_bytes.len()
        )));
    }
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

    fn test_session_key() -> SessionKey {
        SessionKey([42u8; 32])
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let session_key = test_session_key();
        let plaintext = b"hello, agent world";
        let (nonce, ciphertext) = encrypt(&session_key, plaintext).unwrap();
        let decrypted = decrypt(&session_key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key1 = test_session_key();
        let key2 = SessionKey([2u8; 32]);
        let (nonce, ciphertext) = encrypt(&key1, b"secret").unwrap();
        let err = decrypt(&key2, &nonce, &ciphertext).unwrap_err();
        assert!(matches!(err, CatpError::Decryption(_)));
    }

    #[test]
    fn invalid_nonce_length_returns_err_not_panic() {
        let key = test_session_key();
        let bad_nonce = [0u8; 7]; // wrong length
        let result = decrypt(&key, &bad_nonce, b"anything");
        let err = result.unwrap_err();
        assert!(matches!(err, CatpError::Decryption(_)));
    }

    #[test]
    fn tampered_ciphertext_returns_err() {
        let key = test_session_key();
        let (nonce, mut ciphertext) = encrypt(&key, b"sensitive").unwrap();
        ciphertext[0] ^= 0xFF; // flip a byte
        assert!(decrypt(&key, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn static_key_exchange_symmetric() {
        let alice = AgentKeyPair::generate();
        let bob = AgentKeyPair::generate();

        let alice_key = static_key_exchange(&alice, &bob.public_key_bytes()).unwrap();
        let bob_key = static_key_exchange(&bob, &alice.public_key_bytes()).unwrap();

        assert_eq!(alice_key.0, bob_key.0);
    }

    #[test]
    fn static_key_exchange_roundtrip_encrypt_decrypt() {
        let alice = AgentKeyPair::generate();
        let bob = AgentKeyPair::generate();

        let alice_key = static_key_exchange(&alice, &bob.public_key_bytes()).unwrap();
        let bob_key = static_key_exchange(&bob, &alice.public_key_bytes()).unwrap();

        let plaintext = b"shared secret message";
        let (nonce, ciphertext) = encrypt(&alice_key, plaintext).unwrap();
        let decrypted = decrypt(&bob_key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn ephemeral_key_exchange_produces_non_zero_key() {
        let bob = AgentKeyPair::generate();
        let (_ephemeral_pub, session_key) = key_exchange(&bob.public_key_bytes()).unwrap();
        assert_ne!(session_key.0, [0u8; 32]);
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let key = test_session_key();
        let debug_str = format!("{:?}", key);
        assert!(!debug_str.contains("42"));
        assert!(debug_str.contains("REDACTED"));
    }
}
