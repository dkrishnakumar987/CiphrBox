use argon2::password_hash::rand_core::RngCore;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, generic_array::GenericArray};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

pub struct VaultKey {
    pub key: [u8; 32],
}

/// Generates a random 24-byte nonce.
pub fn generate_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    return nonce;
}

/// Derive a chunk-specific nonce from base nonce and chunk index
fn derive_chunk_nonce(base: &[u8; 24], index: u64) -> [u8; 24] {
    let mut nonce = *base;
    nonce[..8].copy_from_slice(&index.to_le_bytes());
    return nonce;
}

/// Encrypt files using XChaCha20-Poly1305 in chunks
pub fn encrypt_file(key: &VaultKey, input_path: &Path, output_path: &Path) {
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&key.key));
    let base_nonce = generate_nonce();

    let input_file = File::open(input_path).expect("Failed to open input file for encryption");
    let mut reader = BufReader::new(input_file);

    let output_file =
        File::create(output_path).expect("Failed to create output file for encrypted data");
    let mut writer = BufWriter::new(output_file);

    writer
        .write_all(&base_nonce)
        .expect("Failed to write base nonce");

    let mut buffer = [0u8; 64 * 1024];
    let mut chunk_index = 0u64;

    loop {
        let read_bytes = reader
            .read(&mut buffer)
            .expect("Failed to read input file chunk");
        if read_bytes == 0 {
            break;
        }

        let chunk_nonce = derive_chunk_nonce(&base_nonce, chunk_index);
        let nonce = XNonce::from_slice(&chunk_nonce);

        let ciphertext = cipher
            .encrypt(nonce, &buffer[..read_bytes])
            .expect("Encryption failed on chunk");

        writer
            .write_u32::<LittleEndian>(ciphertext.len() as u32)
            .expect("Failed to write chunk length");
        writer
            .write_all(&ciphertext)
            .expect("Failed to write encrypted chunk");

        chunk_index += 1;
    }
}

/// Decrypt files using XChaCha20-Poly1305 in chunks
pub fn decrypt_file(key: &VaultKey, input_path: &Path, output_path: &Path) {
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&key.key));

    let input_file = File::open(input_path).expect("Failed to open input file for decryption");
    let mut reader = BufReader::new(input_file);

    let output_file =
        File::create(output_path).expect("Failed to create output file for decrypted data");
    let mut writer = BufWriter::new(output_file);

    let mut base_nonce = [0u8; 24];
    reader
        .read_exact(&mut base_nonce)
        .expect("Failed to read base nonce");

    let mut chunk_index = 0u64;

    loop {
        let len_result = reader.read_u32::<LittleEndian>();
        if let Err(e) = len_result {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                break;
            } else {
                panic!("Failed to read chunk length: {}", e);
            }
        }

        let chunk_len = len_result.expect("Chunk length read failed");
        let mut chunk = vec![0u8; chunk_len as usize];
        reader
            .read_exact(&mut chunk)
            .expect("Failed to read encrypted chunk");

        let chunk_nonce = derive_chunk_nonce(&base_nonce, chunk_index);
        let nonce = XNonce::from_slice(&chunk_nonce);

        let plaintext = cipher
            .decrypt(nonce, chunk.as_ref())
            .expect("Decryption failed on chunk");

        writer
            .write_all(&plaintext)
            .expect("Failed to write decrypted chunk");

        chunk_index += 1;
    }
}

// Unit Tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::tempdir;

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        // Nonces should be 24 bytes
        assert_eq!(nonce1.len(), 24);

        // Two consecutive nonces should be different
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_derive_chunk_nonce() {
        let base_nonce = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        ];

        // First chunk (index 0)
        let chunk0_nonce = derive_chunk_nonce(&base_nonce, 0);
        assert_eq!(&chunk0_nonce[0..8], &[0, 0, 0, 0, 0, 0, 0, 0]); // First 8 bytes replaced with index
        assert_eq!(&chunk0_nonce[8..24], &base_nonce[8..24]); // Rest unchanged

        // Second chunk (index 1)
        let chunk1_nonce = derive_chunk_nonce(&base_nonce, 1);
        assert_eq!(&chunk1_nonce[0..8], &[1, 0, 0, 0, 0, 0, 0, 0]); // First 8 bytes replaced with index
        assert_eq!(&chunk1_nonce[8..24], &base_nonce[8..24]); // Rest unchanged

        // Test with larger index
        let large_chunk_nonce = derive_chunk_nonce(&base_nonce, 0x1234567890ABCDEF);
        assert_eq!(
            &large_chunk_nonce[0..8],
            &[0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12]
        ); // Little endian
        assert_eq!(&large_chunk_nonce[8..24], &base_nonce[8..24]); // Rest unchanged
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Create a temporary directory for test files
        let dir = tempdir().expect("Failed to create temp directory");

        // Create test paths
        let input_path = dir.path().join("original.txt");
        let encrypted_path = dir.path().join("encrypted.bin");
        let decrypted_path = dir.path().join("decrypted.txt");

        // Test data
        let test_data = "This is a test of the encryption and decryption functionality.";

        // Write test data to file
        std::fs::write(&input_path, test_data).expect("Failed to write test data");

        // Create a test key
        let key = VaultKey {
            key: [0x42; 32], // Use a fixed key for testing
        };

        // Encrypt the file
        encrypt_file(&key, &input_path, &encrypted_path);

        // Verify encrypted file exists and is different from original
        assert!(encrypted_path.exists());
        let encrypted_content =
            std::fs::read(&encrypted_path).expect("Failed to read encrypted file");
        assert_ne!(encrypted_content, test_data.as_bytes());

        // Decrypt the file
        decrypt_file(&key, &encrypted_path, &decrypted_path);

        // Verify decrypted content matches original
        let mut decrypted_content = String::new();
        let mut file = File::open(&decrypted_path).expect("Failed to open decrypted file");
        file.read_to_string(&mut decrypted_content)
            .expect("Failed to read decrypted file");

        assert_eq!(decrypted_content, test_data);
    }

    #[test]
    fn test_encrypt_decrypt_large_file() {
        // Create a temporary directory for test files
        let dir = tempdir().expect("Failed to create temp directory");

        // Create test paths
        let input_path = dir.path().join("large.dat");
        let encrypted_path = dir.path().join("large.enc");
        let decrypted_path = dir.path().join("large.dec");

        // Create a large file with multiple chunks (50MB)
        let large_data = vec![0x55; 50 * 1024 * 1024];
        std::fs::write(&input_path, &large_data).expect("Failed to write large test data");

        // Create a test key
        let key = VaultKey {
            key: [0x42; 32], // Use a fixed key for testing
        };

        // Encrypt the file
        encrypt_file(&key, &input_path, &encrypted_path);

        // Decrypt the file
        decrypt_file(&key, &encrypted_path, &decrypted_path);

        // Verify decrypted content matches original
        let decrypted_content =
            std::fs::read(&decrypted_path).expect("Failed to read decrypted file");
        assert_eq!(decrypted_content, large_data);
    }

    #[test]
    fn test_encrypt_decrypt_empty_file() {
        // Create a temporary directory for test files
        let dir = tempdir().expect("Failed to create temp directory");

        // Create test paths
        let input_path = dir.path().join("empty.txt");
        let encrypted_path = dir.path().join("empty.enc");
        let decrypted_path = dir.path().join("empty.dec");

        // Create an empty file
        std::fs::write(&input_path, "").expect("Failed to write empty file");

        // Create a test key
        let key = VaultKey {
            key: [0x42; 32], // Use a fixed key for testing
        };

        // Encrypt the file
        encrypt_file(&key, &input_path, &encrypted_path);

        // Verify encrypted file exists and contains at least the nonce
        let encrypted_content =
            std::fs::read(&encrypted_path).expect("Failed to read encrypted file");
        assert_eq!(encrypted_content.len(), 24); // Only the nonce, no chunks

        // Decrypt the file
        decrypt_file(&key, &encrypted_path, &decrypted_path);

        // Verify decrypted file is empty
        let decrypted_content =
            std::fs::read(&decrypted_path).expect("Failed to read decrypted file");
        assert!(decrypted_content.is_empty());
    }

    #[test]
    #[should_panic(expected = "Decryption failed on chunk")]
    fn test_decrypt_with_wrong_key() {
        // Create a temporary directory for test files
        let dir = tempdir().expect("Failed to create temp directory");

        // Create test paths
        let input_path = dir.path().join("original.txt");
        let encrypted_path = dir.path().join("encrypted.bin");
        let decrypted_path = dir.path().join("decrypted.txt");

        // Test data
        let test_data = "This is test data that should not decrypt with the wrong key.";

        // Write test data to file
        std::fs::write(&input_path, test_data).expect("Failed to write test data");

        // Create a key for encryption
        let key = VaultKey { key: [0x42; 32] };

        // Encrypt the file
        encrypt_file(&key, &input_path, &encrypted_path);

        // Create a different key for decryption
        let wrong_key = VaultKey { key: [0x24; 32] };

        // Attempt to decrypt with wrong key - should panic
        decrypt_file(&wrong_key, &encrypted_path, &decrypted_path);
    }
}
