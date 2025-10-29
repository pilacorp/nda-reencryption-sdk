use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "default-rng")]
use rand_core::OsRng;

use crate::capsule::{Capsule, OpenReencryptedError};
use crate::capsule_frag::VerifiedCapsuleFrag;
use crate::dem::{DecryptionError, EncryptionError, DEM};
use crate::keys::{PublicKey, SecretKey};

use alloc::boxed::Box;
use alloc::vec::Vec;

// Stream processing errors are handled by the underlying DEM and capsule operations

/// Stream encryptor that holds the DEM instance and capsule.
/// This avoids recreating DEM for each chunk.
pub struct StreamEncryptor {
    dem: DEM,
    capsule: Capsule,
    capsule_bytes: Box<[u8]>,
    seq_num: u64,
}

impl StreamEncryptor {
    /// Creates a new stream encryptor.
    pub fn new_with_rng(rng: &mut (impl CryptoRng + RngCore), delegating_pk: &PublicKey) -> Self {
        let (capsule, key_seed) = Capsule::from_public_key(rng, delegating_pk);
        let dem = DEM::new(key_seed.as_secret());
        let capsule_bytes = capsule.to_bytes_simple();

        Self {
            dem,
            capsule,
            capsule_bytes,
            seq_num: 0,
        }
    }

    #[cfg(feature = "default-rng")]
    pub fn new(delegating_pk: &PublicKey) -> Self {
        Self::new_with_rng(&mut OsRng, delegating_pk)
    }

    /// Returns a reference to the capsule (needed for decryption).
    pub fn capsule(&self) -> &Capsule {
        &self.capsule
    }

    /// Encrypts a single chunk. The DEM is reused, avoiding recreation overhead.
    pub fn encrypt_chunk_with_rng(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        chunk: &[u8],
    ) -> Result<Box<[u8]>, EncryptionError> {
        let mut chunk_with_seq = Vec::with_capacity(8 + chunk.len());
        chunk_with_seq.extend_from_slice(&self.seq_num.to_le_bytes());
        chunk_with_seq.extend_from_slice(chunk);

        let encrypted: Box<[u8]> = self
            .dem
            .encrypt(rng, &chunk_with_seq, &self.capsule_bytes)?;
        self.seq_num += 1;

        Ok(encrypted)
    }

    #[cfg(feature = "default-rng")]
    pub fn encrypt_chunk(&mut self, chunk: &[u8]) -> Result<Box<[u8]>, EncryptionError> {
        self.encrypt_chunk_with_rng(&mut OsRng, chunk)
    }

    /// Processes a stream using callbacks.
    ///
    /// `read_callback` is called repeatedly to get input chunks. Return None to signal end.
    /// `write_callback` is called for each encrypted chunk.
    ///
    /// This allows streaming without repeatedly crossing the FFI boundary.
    pub fn process_stream_with_rng<R, W>(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        mut read_callback: R,
        mut write_callback: W,
    ) -> Result<(), EncryptionError>
    where
        R: FnMut() -> Option<Vec<u8>>,
        W: FnMut(&[u8]) -> bool, // Returns false on error
    {
        while let Some(chunk) = read_callback() {
            let encrypted = self.encrypt_chunk_with_rng(rng, &chunk)?;
            if !write_callback(&encrypted) {
                return Err(EncryptionError::PlaintextTooLarge);
            }
        }
        Ok(())
    }

    #[cfg(feature = "default-rng")]
    pub fn process_stream<R, W>(
        &mut self,
        read_callback: R,
        write_callback: W,
    ) -> Result<(), EncryptionError>
    where
        R: FnMut() -> Option<Vec<u8>>,
        W: FnMut(&[u8]) -> bool,
    {
        self.process_stream_with_rng(&mut OsRng, read_callback, write_callback)
    }
}

/// Stream decryptor that holds the DEM instance.
/// This avoids recreating DEM for each chunk.
pub struct StreamDecryptor {
    dem: DEM,
    capsule_bytes: Box<[u8]>,
    seq_num: u64,
}

impl StreamDecryptor {
    /// Creates a stream decryptor for original key.
    pub fn new_original(delegating_sk: &SecretKey, capsule: &Capsule) -> Self {
        let key_seed = capsule.open_original(delegating_sk);
        let dem = DEM::new(key_seed.as_secret());
        let capsule_bytes = capsule.to_bytes_simple();

        Self {
            dem,
            capsule_bytes,
            seq_num: 0,
        }
    }

    /// Creates a stream decryptor for re-encrypted data.
    pub fn new_reencrypted(
        receiving_sk: &SecretKey,
        delegating_pk: &PublicKey,
        capsule: &Capsule,
        verified_cfrags: impl IntoIterator<Item = VerifiedCapsuleFrag>,
    ) -> Result<Self, OpenReencryptedError> {
        let cfrags: Vec<_> = verified_cfrags
            .into_iter()
            .map(|vcfrag| vcfrag.unverify())
            .collect();
        let key_seed = capsule.open_reencrypted(receiving_sk, delegating_pk, &cfrags)?;
        let dem = DEM::new(key_seed.as_secret());
        let capsule_bytes = capsule.to_bytes_simple();

        Ok(Self {
            dem,
            capsule_bytes,
            seq_num: 0,
        })
    }

    /// Decrypts a single chunk. The DEM is reused, avoiding recreation overhead.
    pub fn decrypt_chunk(&mut self, encrypted_chunk: &[u8]) -> Result<Box<[u8]>, DecryptionError> {
        let chunk_with_seq = self.dem.decrypt(encrypted_chunk, &self.capsule_bytes)?;

        if chunk_with_seq.len() < 8 {
            return Err(DecryptionError::DataError);
        }

        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&chunk_with_seq[..8]);
        let stored_seq = u64::from_le_bytes(seq_bytes);

        if stored_seq != self.seq_num {
            return Err(DecryptionError::DataError);
        }

        self.seq_num += 1;
        Ok(chunk_with_seq[8..].into())
    }

    /// Processes a stream using callbacks.
    ///
    /// `read_callback` is called repeatedly to get encrypted chunks. Return None to signal end.
    /// `write_callback` is called for each decrypted chunk.
    pub fn process_stream<R, W>(
        &mut self,
        mut read_callback: R,
        mut write_callback: W,
    ) -> Result<(), DecryptionError>
    where
        R: FnMut() -> Option<Vec<u8>>,
        W: FnMut(&[u8]) -> bool, // Returns false on error
    {
        while let Some(encrypted_chunk) = read_callback() {
            let decrypted = self.decrypt_chunk(&encrypted_chunk)?;
            if !write_callback(&decrypted) {
                return Err(DecryptionError::DataError);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use alloc::vec::Vec;

    use crate::SecretKey;

    use super::{StreamDecryptor, StreamEncryptor};

    #[test]
    fn test_stream_encryptor() {
        let delegating_sk = SecretKey::random();
        let delegating_pk = delegating_sk.public_key();

        // Create stream encryptor once
        let mut encryptor = StreamEncryptor::new(&delegating_pk);

        // Encrypt multiple chunks
        let chunks =
            Vec::<Vec<u8>>::from([b"chunk1".to_vec(), b"chunk2".to_vec(), b"chunk3".to_vec()]);
        let mut encrypted_chunks = Vec::new();

        for chunk in &chunks {
            encrypted_chunks.push(encryptor.encrypt_chunk(chunk).unwrap());
        }

        // Create stream decryptor once
        let mut decryptor = StreamDecryptor::new_original(&delegating_sk, encryptor.capsule());

        // Decrypt chunks
        for (i, encrypted) in encrypted_chunks.iter().enumerate() {
            let decrypted = decryptor.decrypt_chunk(encrypted).unwrap();
            assert_eq!(&*decrypted, chunks[i].as_slice());
        }
    }

    #[test]
    fn test_stream_with_callbacks() {
        let delegating_sk = SecretKey::random();
        let delegating_pk = delegating_sk.public_key();

        let chunks = Vec::<Vec<u8>>::from([b"data1".to_vec(), b"data2".to_vec()]);
        let mut encrypted_output = Vec::new();

        // Encrypt using callbacks
        let mut encryptor = StreamEncryptor::new(&delegating_pk);
        let mut chunk_idx = 0;

        encryptor
            .process_stream(
                || {
                    if chunk_idx < chunks.len() {
                        let chunk = chunks[chunk_idx].clone();
                        chunk_idx += 1;
                        Some(chunk)
                    } else {
                        None
                    }
                },
                |encrypted| {
                    encrypted_output.push(encrypted.to_vec());
                    true
                },
            )
            .unwrap();

        // Decrypt using callbacks
        let mut decryptor = StreamDecryptor::new_original(&delegating_sk, encryptor.capsule());
        let mut decrypted_output = Vec::new();
        let mut enc_idx = 0;

        decryptor
            .process_stream(
                || {
                    if enc_idx < encrypted_output.len() {
                        let chunk = encrypted_output[enc_idx].clone();
                        enc_idx += 1;
                        Some(chunk)
                    } else {
                        None
                    }
                },
                |decrypted| {
                    decrypted_output.push(decrypted.to_vec());
                    true
                },
            )
            .unwrap();

        // Verify
        assert_eq!(decrypted_output.len(), chunks.len());
        for (i, decrypted) in decrypted_output.iter().enumerate() {
            assert_eq!(decrypted.as_slice(), chunks[i].as_slice());
        }
    }
}
