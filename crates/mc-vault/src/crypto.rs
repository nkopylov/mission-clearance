use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Result, bail};
use argon2::Argon2;
use rand::RngCore;
use zeroize::Zeroize;

/// Nonce size for AES-256-GCM (96 bits / 12 bytes).
const NONCE_LEN: usize = 12;

/// Derive a 256-bit key from a passphrase and salt using Argon2id.
///
/// Uses the default Argon2id parameters (19 MiB memory, 2 iterations, 1 lane).
pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2 key derivation failed: {e}"))?;
    Ok(key)
}

/// Generate a cryptographically random 32-byte salt.
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Encrypt `plaintext` with AES-256-GCM using the given 256-bit key.
///
/// Returns `nonce || ciphertext` (12 bytes nonce followed by the ciphertext + auth tag).
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid key length"))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data that was produced by [`encrypt`].
///
/// Expects `data` to be `nonce || ciphertext` (first 12 bytes are the nonce).
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN {
        bail!("ciphertext too short: expected at least {NONCE_LEN} bytes for nonce");
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid key length"))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("decryption failed (wrong key or corrupted data): {e}"))?;

    Ok(plaintext)
}

/// Securely zero out a key. Call this when you are done with the key material.
pub fn zeroize_key(key: &mut [u8; 32]) {
    key.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_key("test-passphrase", b"0123456789abcdef0123456789abcdef").unwrap();
        let plaintext = b"super secret api key: sk-12345";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = derive_key("passphrase-one", b"0123456789abcdef0123456789abcdef").unwrap();
        let key2 = derive_key("passphrase-two", b"0123456789abcdef0123456789abcdef").unwrap();

        let encrypted = encrypt(&key1, b"secret data").unwrap();
        let result = decrypt(&key2, &encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn different_encryptions_produce_different_output() {
        let key = derive_key("same-passphrase", b"0123456789abcdef0123456789abcdef").unwrap();
        let plaintext = b"same plaintext";

        let enc1 = encrypt(&key, plaintext).unwrap();
        let enc2 = encrypt(&key, plaintext).unwrap();

        // Because of random nonces, two encryptions of the same plaintext differ.
        assert_ne!(enc1, enc2);

        // But both decrypt to the same value.
        assert_eq!(decrypt(&key, &enc1).unwrap(), plaintext);
        assert_eq!(decrypt(&key, &enc2).unwrap(), plaintext);
    }

    #[test]
    fn decrypt_too_short_data_fails() {
        let key = [0u8; 32];
        let result = decrypt(&key, &[0u8; 5]);
        assert!(result.is_err());
    }

    #[test]
    fn generate_salt_is_random() {
        let s1 = generate_salt();
        let s2 = generate_salt();
        assert_ne!(s1, s2);
    }

    #[test]
    fn derive_key_deterministic() {
        let salt = b"0123456789abcdef0123456789abcdef";
        let k1 = derive_key("same-pass", salt).unwrap();
        let k2 = derive_key("same-pass", salt).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn zeroize_key_works() {
        let mut key = derive_key("pass", b"0123456789abcdef0123456789abcdef").unwrap();
        assert_ne!(key, [0u8; 32]);
        zeroize_key(&mut key);
        assert_eq!(key, [0u8; 32]);
    }
}
