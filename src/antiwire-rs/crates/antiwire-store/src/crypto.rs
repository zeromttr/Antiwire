//! Application-level encryption for sensitive settings fields.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use antiwire_secrets::SecretBytes;
use zeroize::Zeroizing;

use crate::error::{Result, StoreError};

const V1_PREFIX: &str = "enc:v1:";
const V2_PREFIX: &str = "enc:v2:";
const GCM_NONCE_LEN: usize = 12;

/// Encrypts plaintext as an authenticated, versioned AES-256-GCM record.
pub(crate) fn encrypt_field(plaintext: &str, key: &SecretBytes) -> Result<String> {
    if plaintext.is_empty() {
        return Ok(String::new());
    }

    let cipher_key = field_key(key.expose_secret());
    let cipher = Aes256Gcm::new_from_slice(cipher_key.as_ref())
        .map_err(|_| StoreError::Crypto("invalid cipher key".to_owned()))?;
    let nonce = random_bytes::<GCM_NONCE_LEN>()?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|_| StoreError::Crypto("encrypt failed".to_owned()))?;

    let mut payload = nonce.to_vec();
    payload.extend_from_slice(&ciphertext);
    Ok(format!("{V2_PREFIX}{}", base64_encode(&payload)))
}

/// Decrypts a field; returns plaintext for legacy unencrypted values.
pub(crate) fn decrypt_field(value: &str, key: &SecretBytes) -> Result<String> {
    if value.is_empty() {
        return Ok(String::new());
    }

    if let Some(encoded) = value.strip_prefix(V2_PREFIX) {
        return decrypt_v2(encoded, key);
    }
    if let Some(encoded) = value.strip_prefix(V1_PREFIX) {
        return decrypt_v1(encoded, key);
    }
    Ok(value.to_owned())
}

fn decrypt_v2(encoded: &str, key: &SecretBytes) -> Result<String> {
    let payload = base64_decode(encoded)?;
    if payload.len() <= GCM_NONCE_LEN {
        return Err(StoreError::Crypto("encrypted payload too short".to_owned()));
    }

    let (nonce, ciphertext) = payload.split_at(GCM_NONCE_LEN);
    let cipher_key = field_key(key.expose_secret());
    let cipher = Aes256Gcm::new_from_slice(cipher_key.as_ref())
        .map_err(|_| StoreError::Crypto("invalid cipher key".to_owned()))?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| StoreError::Crypto("authentication failed".to_owned()))?,
    );
    String::from_utf8(plain.to_vec()).map_err(|_| StoreError::Crypto("invalid utf8".to_owned()))
}

fn decrypt_v1(encoded: &str, key: &SecretBytes) -> Result<String> {
    let payload = base64_decode(encoded)?;
    if payload.len() < 16 {
        return Err(StoreError::Crypto("encrypted payload too short".to_owned()));
    }

    let (iv, ciphertext) = payload.split_at(16);
    let cipher_key = field_key(key.expose_secret());
    let plain = Zeroizing::new(aes256_cbc_decrypt(&cipher_key, iv, ciphertext)?);
    String::from_utf8(plain.to_vec()).map_err(|_| StoreError::Crypto("invalid utf8".to_owned()))
}

fn field_key(master: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = [0_u8; 32];
    let len = master.len().min(32);
    out[..len].copy_from_slice(&master[..len]);
    Zeroizing::new(out)
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes)
        .map_err(|error| StoreError::Crypto(format!("secure random source failed: {error}")))?;
    Ok(bytes)
}

#[cfg(test)]
fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
    let cipher = Aes256CbcEnc::new_from_slices(key, iv)
        .map_err(|_| StoreError::Crypto("invalid cipher params".to_owned()))?;
    let padded_len = ((data.len() / 16) + 1) * 16;
    let mut buffer = vec![0_u8; padded_len];
    let ciphertext = cipher
        .encrypt_padded_b2b_mut::<Pkcs7>(data, &mut buffer)
        .map_err(|_| StoreError::Crypto("encrypt failed".to_owned()))?;
    Ok(ciphertext.to_vec())
}

fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};

    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
    let cipher = Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|_| StoreError::Crypto("invalid cipher params".to_owned()))?;
    let mut buffer = data.to_vec();
    let plain = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| StoreError::Crypto("decrypt failed".to_owned()))?;
    Ok(plain.to_vec())
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(text: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|error| StoreError::Crypto(error.to_string()))
}

#[cfg(test)]
pub(crate) fn encrypt_v1_for_test(plaintext: &str, key: &SecretBytes) -> String {
    let cipher_key = field_key(key.expose_secret());
    let iv = [0xA5; 16];
    let ciphertext =
        aes256_cbc_encrypt(&cipher_key, &iv, plaintext.as_bytes()).expect("legacy encrypt");
    let mut payload = iv.to_vec();
    payload.extend_from_slice(&ciphertext);
    format!("{V1_PREFIX}{}", base64_encode(&payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SecretBytes {
        SecretBytes::new(vec![byte; 32])
    }

    #[test]
    fn v2_round_trip() {
        let encrypted = encrypt_field("top secret", &key(7)).expect("encrypt");
        assert!(encrypted.starts_with(V2_PREFIX));
        assert_eq!(
            decrypt_field(&encrypted, &key(7)).expect("decrypt"),
            "top secret"
        );
    }

    #[test]
    fn rejects_wrong_key_and_tampering() {
        let encrypted = encrypt_field("top secret", &key(7)).expect("encrypt");
        assert!(decrypt_field(&encrypted, &key(8)).is_err());

        let mut payload = base64_decode(encrypted.strip_prefix(V2_PREFIX).unwrap()).unwrap();
        *payload.last_mut().unwrap() ^= 1;
        let tampered = format!("{V2_PREFIX}{}", base64_encode(&payload));
        assert!(decrypt_field(&tampered, &key(7)).is_err());
    }

    #[test]
    fn reads_legacy_v1_and_plaintext() {
        let legacy = encrypt_v1_for_test("legacy secret", &key(7));
        assert_eq!(
            decrypt_field(&legacy, &key(7)).expect("legacy decrypt"),
            "legacy secret"
        );
        assert_eq!(
            decrypt_field("not encrypted", &key(7)).expect("plaintext"),
            "not encrypted"
        );
    }
}
