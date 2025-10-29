//! C FFI bindings for umbral-pre
//!
//! This module provides C-compatible FFI bindings that can be used from Go via CGO.

// Allow unsafe code for FFI
#![allow(unsafe_code)]

use crate::dem::DEM;
use crate::{
    decrypt_original, decrypt_reencrypted, encrypt, generate_kfrags, reencrypt, Capsule,
    CapsuleFrag, KeyFrag, PublicKey, SecretKey, Signer, VerifiedCapsuleFrag, VerifiedKeyFrag,
};
use alloc::boxed::Box;
use alloc::format;
use alloc::vec::{self, Vec};
use core::ptr;
use core::slice;
use rand_core::OsRng;

use crate::{StreamDecryptor, StreamEncryptor};

// ============================================================================
// Error handling
// ============================================================================

#[repr(C)]
pub struct UmbralError {
    pub code: i32,
    pub message: *mut u8,
    pub message_len: usize,
}

impl UmbralError {
    fn success() -> Self {
        Self {
            code: 0,
            message: ptr::null_mut(),
            message_len: 0,
        }
    }

    fn from_string(code: i32, msg: alloc::string::String) -> Self {
        let mut bytes = msg.into_bytes().into_boxed_slice();
        let len = bytes.len();
        let ptr = bytes.as_mut_ptr();
        core::mem::forget(bytes);
        Self {
            code,
            message: ptr,
            message_len: len,
        }
    }
}

// ============================================================================
// Opaque pointers for Rust types
// ============================================================================

pub type SecretKeyPtr = *mut SecretKey;
pub type PublicKeyPtr = *mut PublicKey;
pub type SignerPtr = *mut Signer;
pub type CapsulePtr = *mut Capsule;
pub type KeyFragPtr = *mut KeyFrag;
pub type VerifiedKeyFragPtr = *mut VerifiedKeyFrag;
pub type CapsuleFragPtr = *mut CapsuleFrag;
pub type VerifiedCapsuleFragPtr = *mut VerifiedCapsuleFrag;
pub type StreamEncryptorPtr = *mut StreamEncryptor;
pub type StreamDecryptorPtr = *mut StreamDecryptor;
pub type DEMPtr = *mut DEM;
pub type ReadCallback =
    extern "C" fn(ctx: *mut core::ffi::c_void, buf: *mut u8, buf_len: usize) -> isize;
pub type WriteCallback =
    extern "C" fn(ctx: *mut core::ffi::c_void, data: *const u8, data_len: usize) -> i32;

// ============================================================================
// Buffer management
// ============================================================================

#[repr(C)]
pub struct ByteBuffer {
    pub data: *mut u8,
    pub len: usize,
}

impl ByteBuffer {
    fn from_vec(mut v: Vec<u8>) -> Self {
        let len = v.len();
        let data = v.as_mut_ptr();
        core::mem::forget(v);
        Self { data, len }
    }

    fn from_boxed_slice(mut b: Box<[u8]>) -> Self {
        let len = b.len();
        let data = b.as_mut_ptr();
        core::mem::forget(b);
        Self { data, len }
    }
}

#[no_mangle]
pub extern "C" fn umbral_byte_buffer_free(buf: ByteBuffer) {
    if !buf.data.is_null() && buf.len > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(buf.data, buf.len, buf.len);
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_error_free(err: UmbralError) {
    if !err.message.is_null() && err.message_len > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(err.message, err.message_len, err.message_len);
        }
    }
}

// ============================================================================
// Capsule
// ============================================================================

#[no_mangle]
pub extern "C" fn umbral_capsule_to_bytes_simple(capsule: CapsulePtr) -> ByteBuffer {
    if capsule.is_null() {
        return ByteBuffer::from_vec(Vec::new());
    }
    unsafe {
        let bytes = (*capsule).to_bytes_simple();
        ByteBuffer::from_boxed_slice(bytes)
    }
}

#[no_mangle]
pub extern "C" fn umbral_capsule_to_bytes(capsule: CapsulePtr) -> ByteBuffer {
    if capsule.is_null() {
        return ByteBuffer::from_vec(Vec::new());
    }
    unsafe {
        match <Capsule as crate::traits::DefaultSerialize>::to_bytes(&*capsule) {
            Ok(bytes) => ByteBuffer::from_vec(bytes.into_vec()),
            Err(_) => ByteBuffer::from_vec(Vec::new()),
        }
    }
}

// ============================================================================
// Key generation
// ============================================================================

#[no_mangle]
pub extern "C" fn umbral_secret_key_random() -> SecretKeyPtr {
    Box::into_raw(Box::new(SecretKey::random()))
}

#[no_mangle]
pub extern "C" fn umbral_secret_key_from_bytes(
    bytes: *const u8,
    bytes_len: usize,
    sk_out: *mut SecretKeyPtr,
    error_out: *mut UmbralError,
) -> i32 {
    if bytes.is_null() || sk_out.is_null() {
        if !error_out.is_null() {
            unsafe {
                *error_out = UmbralError::from_string(-1, "Null pointer passed".into());
            }
        }
        return -1;
    }

    unsafe {
        let bytes_slice = slice::from_raw_parts(bytes, bytes_len);
        match SecretKey::try_from_be_bytes(bytes_slice) {
            Ok(sk) => {
                *sk_out = Box::into_raw(Box::new(sk));
                if !error_out.is_null() {
                    *error_out = UmbralError::success();
                }
                0
            }
            Err(e) => {
                if !error_out.is_null() {
                    *error_out = UmbralError::from_string(-2, alloc::format!("{:?}", e));
                }
                -2
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_secret_key_free(sk: SecretKeyPtr) {
    if !sk.is_null() {
        unsafe {
            let _ = Box::from_raw(sk);
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_secret_key_public_key(sk: SecretKeyPtr) -> PublicKeyPtr {
    if sk.is_null() {
        return ptr::null_mut();
    }
    unsafe { Box::into_raw(Box::new((*sk).public_key())) }
}

#[no_mangle]
pub extern "C" fn umbral_public_key_free(pk: PublicKeyPtr) {
    if !pk.is_null() {
        unsafe {
            let _ = Box::from_raw(pk);
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_public_key_from_bytes(
    bytes: *const u8,
    bytes_len: usize,
    pk_out: *mut PublicKeyPtr,
    error_out: *mut UmbralError,
) -> i32 {
    if bytes.is_null() || pk_out.is_null() {
        if !error_out.is_null() {
            unsafe {
                *error_out = UmbralError::from_string(-1, "Null pointer passed".into());
            }
        }
        return -1;
    }

    unsafe {
        let bytes_slice = slice::from_raw_parts(bytes, bytes_len);
        match PublicKey::try_from_compressed_bytes(bytes_slice) {
            Ok(pk) => {
                *pk_out = Box::into_raw(Box::new(pk));
                if !error_out.is_null() {
                    *error_out = UmbralError::success();
                }
                0
            }
            Err(e) => {
                if !error_out.is_null() {
                    *error_out = UmbralError::from_string(-2, alloc::format!("{:?}", e));
                }
                -2
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_secret_key_to_bytes(sk: SecretKeyPtr) -> ByteBuffer {
    if sk.is_null() {
        return ByteBuffer::from_vec(Vec::new());
    }
    unsafe {
        let secret_box = (*sk).to_be_bytes();
        let bytes: Vec<u8> = secret_box.as_secret().iter().cloned().collect();
        ByteBuffer::from_vec(bytes)
    }
}

#[no_mangle]
pub extern "C" fn umbral_public_key_to_bytes(pk: PublicKeyPtr) -> ByteBuffer {
    if pk.is_null() {
        return ByteBuffer::from_vec(Vec::new());
    }
    unsafe {
        let bytes_slice = (*pk).to_compressed_bytes();
        let bytes: Vec<u8> = bytes_slice.iter().cloned().collect();
        ByteBuffer::from_vec(bytes)
    }
}

// ============================================================================
// Signer
// ============================================================================

#[no_mangle]
pub extern "C" fn umbral_signer_new(sk: SecretKeyPtr) -> SignerPtr {
    if sk.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        let signer = Signer::new((*sk).clone());
        Box::into_raw(Box::new(signer))
    }
}

#[no_mangle]
pub extern "C" fn umbral_signer_free(signer: SignerPtr) {
    if !signer.is_null() {
        unsafe {
            let _ = Box::from_raw(signer);
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_signer_verifying_key(signer: SignerPtr) -> PublicKeyPtr {
    if signer.is_null() {
        return ptr::null_mut();
    }
    unsafe { Box::into_raw(Box::new((*signer).verifying_key())) }
}

// ============================================================================
// Encryption/Decryption
// ============================================================================

#[no_mangle]
pub extern "C" fn umbral_encrypt(
    pk: PublicKeyPtr,
    plaintext: *const u8,
    plaintext_len: usize,
    capsule_out: *mut CapsulePtr,
    ciphertext_out: *mut ByteBuffer,
    error_out: *mut UmbralError,
) -> i32 {
    if pk.is_null() || plaintext.is_null() || capsule_out.is_null() || ciphertext_out.is_null() {
        if !error_out.is_null() {
            unsafe {
                *error_out = UmbralError::from_string(-1, "Null pointer passed".into());
            }
        }
        return -1;
    }

    unsafe {
        let plaintext_slice = slice::from_raw_parts(plaintext, plaintext_len);
        match encrypt(&*pk, plaintext_slice) {
            Ok((capsule, ciphertext)) => {
                *capsule_out = Box::into_raw(Box::new(capsule));
                *ciphertext_out = ByteBuffer::from_boxed_slice(ciphertext);
                if !error_out.is_null() {
                    *error_out = UmbralError::success();
                }
                0
            }
            Err(e) => {
                if !error_out.is_null() {
                    *error_out = UmbralError::from_string(-2, alloc::format!("{:?}", e));
                }
                -2
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_decrypt_original(
    sk: SecretKeyPtr,
    capsule: CapsulePtr,
    ciphertext: *const u8,
    ciphertext_len: usize,
    plaintext_out: *mut ByteBuffer,
    error_out: *mut UmbralError,
) -> i32 {
    if sk.is_null() || capsule.is_null() || ciphertext.is_null() || plaintext_out.is_null() {
        if !error_out.is_null() {
            unsafe {
                *error_out = UmbralError::from_string(-1, "Null pointer passed".into());
            }
        }
        return -1;
    }

    unsafe {
        let ciphertext_slice = slice::from_raw_parts(ciphertext, ciphertext_len);
        match decrypt_original(&*sk, &*capsule, ciphertext_slice) {
            Ok(plaintext) => {
                *plaintext_out = ByteBuffer::from_boxed_slice(plaintext);
                if !error_out.is_null() {
                    *error_out = UmbralError::success();
                }
                0
            }
            Err(e) => {
                if !error_out.is_null() {
                    *error_out = UmbralError::from_string(-3, alloc::format!("{:?}", e));
                }
                -3
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_capsule_free(capsule: CapsulePtr) {
    if !capsule.is_null() {
        unsafe {
            let _ = Box::from_raw(capsule);
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_capsule_from_public_key(
    pk: PublicKeyPtr,
    capsule_out: *mut CapsulePtr,
    key_seed_out: *mut ByteBuffer,
    error_out: *mut UmbralError,
) -> i32 {
    if pk.is_null() || capsule_out.is_null() || key_seed_out.is_null() {
        if !error_out.is_null() {
            unsafe {
                *error_out = UmbralError::from_string(-1, "Null pointer passed".into());
            }
        }
        return -1;
    }

    unsafe {
        let mut rng = OsRng;
        let (capsule, key_seed) = Capsule::from_public_key(&mut rng, &*pk);
        *capsule_out = Box::into_raw(Box::new(capsule));
        *key_seed_out =
            ByteBuffer::from_boxed_slice(key_seed.as_secret().to_vec().into_boxed_slice());
        if !error_out.is_null() {
            *error_out = UmbralError::success();
        }
        0
    }
}

#[no_mangle]
pub extern "C" fn umbral_capsule_from_bytes(
    bytes: *const u8,
    bytes_len: usize,
    capsule_out: *mut CapsulePtr,
    error_out: *mut UmbralError,
) -> i32 {
    if bytes.is_null() || capsule_out.is_null() {
        if !error_out.is_null() {
            unsafe {
                *error_out = UmbralError::from_string(-1, "Null pointer passed".into());
            }
        }
        return -1;
    }

    unsafe {
        let bytes_slice = slice::from_raw_parts(bytes, bytes_len);
        match <Capsule as crate::traits::DefaultDeserialize>::from_bytes(bytes_slice) {
            Ok(capsule) => {
                *capsule_out = Box::into_raw(Box::new(capsule));
                if !error_out.is_null() {
                    *error_out = UmbralError::success();
                }
                0
            }
            Err(e) => {
                if !error_out.is_null() {
                    *error_out = UmbralError::from_string(
                        -2,
                        format!("Failed to deserialize capsule: {}", e).into(),
                    );
                }
                -2
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_key_frag_from_bytes(
    bytes: *const u8,
    bytes_len: usize,
    kfrag_out: *mut KeyFragPtr,
    error_out: *mut UmbralError,
) -> i32 {
    if bytes.is_null() || kfrag_out.is_null() {
        if !error_out.is_null() {
            unsafe {
                *error_out = UmbralError::from_string(-1, "Null pointer passed".into());
            }
        }
        return -1;
    }

    unsafe {
        let bytes_slice = slice::from_raw_parts(bytes, bytes_len);
        match <KeyFrag as crate::traits::DefaultDeserialize>::from_bytes(bytes_slice) {
            Ok(kfrag) => {
                *kfrag_out = Box::into_raw(Box::new(kfrag));
                if !error_out.is_null() {
                    *error_out = UmbralError::success();
                }
                0
            }
            Err(e) => {
                if !error_out.is_null() {
                    *error_out = UmbralError::from_string(
                        -2,
                        format!("Failed to deserialize key frag: {}", e).into(),
                    );
                }
                -2
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_key_frag_to_bytes(kfrag: KeyFragPtr) -> ByteBuffer {
    if kfrag.is_null() {
        return ByteBuffer::from_vec(Vec::new());
    }
    unsafe {
        match <KeyFrag as crate::traits::DefaultSerialize>::to_bytes(&*kfrag) {
            Ok(bytes) => ByteBuffer::from_vec(bytes.into_vec()),
            Err(_) => ByteBuffer::from_vec(Vec::new()),
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_capsule_frag_to_bytes(vcfrag: VerifiedCapsuleFragPtr) -> ByteBuffer {
    if vcfrag.is_null() {
        return ByteBuffer::from_vec(Vec::new());
    }
    unsafe {
        match <VerifiedCapsuleFrag as crate::traits::DefaultSerialize>::to_bytes(&*vcfrag) {
            Ok(bytes) => ByteBuffer::from_vec(bytes.into_vec()),
            Err(_) => ByteBuffer::from_vec(Vec::new()),
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_capsule_frag_from_bytes(
    bytes: *const u8,
    bytes_len: usize,
    vcfrag_out: *mut VerifiedCapsuleFragPtr,
    error_out: *mut UmbralError,
) -> i32 {
    if bytes.is_null() || vcfrag_out.is_null() {
        if !error_out.is_null() {
            unsafe {
                *error_out = UmbralError::from_string(-1, "Null pointer passed".into());
            }
        }
        return -1;
    }

    unsafe {
        let bytes_slice = slice::from_raw_parts(bytes, bytes_len);
        match <VerifiedCapsuleFrag as crate::traits::DefaultDeserialize>::from_bytes(bytes_slice) {
            Ok(vcfrag) => {
                *vcfrag_out = Box::into_raw(Box::new(vcfrag));
                if !error_out.is_null() {
                    *error_out = UmbralError::success();
                }
                0
            }
            Err(e) => {
                if !error_out.is_null() {
                    *error_out = UmbralError::from_string(
                        -2,
                        format!("Failed to deserialize capsule frag: {}", e).into(),
                    );
                }
                -2
            }
        }
    }
}

// ============================================================================
// Key Fragment generation
// ============================================================================

#[no_mangle]
pub extern "C" fn umbral_generate_kfrags(
    delegating_sk: SecretKeyPtr,
    receiving_pk: PublicKeyPtr,
    signer: SignerPtr,
    threshold: usize,
    shares: usize,
    sign_delegating_key: bool,
    sign_receiving_key: bool,
    kfrags_out: *mut *mut VerifiedKeyFragPtr,
    error_out: *mut UmbralError,
) -> i32 {
    if delegating_sk.is_null() || receiving_pk.is_null() || signer.is_null() || kfrags_out.is_null()
    {
        if !error_out.is_null() {
            unsafe {
                *error_out = UmbralError::from_string(-1, "Null pointer passed".into());
            }
        }
        return -1;
    }

    unsafe {
        let kfrags = generate_kfrags(
            &*delegating_sk,
            &*receiving_pk,
            &*signer,
            threshold,
            shares,
            sign_delegating_key,
            sign_receiving_key,
        );

        // Convert Box<[VerifiedKeyFrag]> to array of pointers
        let mut kfrag_ptrs: Vec<VerifiedKeyFragPtr> = Vec::new();
        for kfrag in kfrags.iter() {
            kfrag_ptrs.push(Box::into_raw(Box::new(kfrag.clone())));
        }

        let mut kfrag_ptrs_boxed = kfrag_ptrs.into_boxed_slice();
        let ptr = kfrag_ptrs_boxed.as_mut_ptr();
        core::mem::forget(kfrag_ptrs_boxed);

        *kfrags_out = ptr;

        if !error_out.is_null() {
            *error_out = UmbralError::success();
        }
        shares as i32
    }
}

#[no_mangle]
pub extern "C" fn umbral_verified_kfrag_free(kfrag: VerifiedKeyFragPtr) {
    if !kfrag.is_null() {
        unsafe {
            let _ = Box::from_raw(kfrag);
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_verified_kfrag_unverify(kfrag: VerifiedKeyFragPtr) -> KeyFragPtr {
    if kfrag.is_null() {
        return ptr::null_mut();
    }
    unsafe { Box::into_raw(Box::new((*kfrag).clone().unverify())) }
}

#[no_mangle]
pub extern "C" fn umbral_kfrag_free(kfrag: KeyFragPtr) {
    if !kfrag.is_null() {
        unsafe {
            let _ = Box::from_raw(kfrag);
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_kfrag_verify(
    kfrag: KeyFragPtr,
    verifying_pk: PublicKeyPtr,
    delegating_pk: PublicKeyPtr,
    receiving_pk: PublicKeyPtr,
    verified_kfrag_out: *mut VerifiedKeyFragPtr,
    error_out: *mut UmbralError,
) -> i32 {
    if kfrag.is_null() || verifying_pk.is_null() || verified_kfrag_out.is_null() {
        if !error_out.is_null() {
            unsafe {
                *error_out = UmbralError::from_string(-1, "Null pointer passed".into());
            }
        }
        return -1;
    }

    unsafe {
        let delegating = if delegating_pk.is_null() {
            None
        } else {
            Some(&*delegating_pk)
        };
        let receiving = if receiving_pk.is_null() {
            None
        } else {
            Some(&*receiving_pk)
        };

        match (*kfrag)
            .clone()
            .verify(&*verifying_pk, delegating, receiving)
        {
            Ok(verified) => {
                *verified_kfrag_out = Box::into_raw(Box::new(verified));
                if !error_out.is_null() {
                    *error_out = UmbralError::success();
                }
                0
            }
            Err(e) => {
                if !error_out.is_null() {
                    *error_out = UmbralError::from_string(-4, alloc::format!("{:?}", e));
                }
                -4
            }
        }
    }
}

// ============================================================================
// Re-encryption
// ============================================================================

#[no_mangle]
pub extern "C" fn umbral_reencrypt(
    capsule: CapsulePtr,
    verified_kfrag: VerifiedKeyFragPtr,
    verified_cfrag_out: *mut VerifiedCapsuleFragPtr,
    error_out: *mut UmbralError,
) -> i32 {
    if capsule.is_null() || verified_kfrag.is_null() || verified_cfrag_out.is_null() {
        if !error_out.is_null() {
            unsafe {
                *error_out = UmbralError::from_string(-1, "Null pointer passed".into());
            }
        }
        return -1;
    }

    unsafe {
        let cfrag = reencrypt(&*capsule, (*verified_kfrag).clone());
        *verified_cfrag_out = Box::into_raw(Box::new(cfrag));
        if !error_out.is_null() {
            *error_out = UmbralError::success();
        }
        0
    }
}

#[no_mangle]
pub extern "C" fn umbral_verified_cfrag_free(cfrag: VerifiedCapsuleFragPtr) {
    if !cfrag.is_null() {
        unsafe {
            let _ = Box::from_raw(cfrag);
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_verified_cfrag_unverify(cfrag: VerifiedCapsuleFragPtr) -> CapsuleFragPtr {
    if cfrag.is_null() {
        return ptr::null_mut();
    }
    unsafe { Box::into_raw(Box::new((*cfrag).clone().unverify())) }
}

#[no_mangle]
pub extern "C" fn umbral_cfrag_free(cfrag: CapsuleFragPtr) {
    if !cfrag.is_null() {
        unsafe {
            let _ = Box::from_raw(cfrag);
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_cfrag_verify(
    cfrag: CapsuleFragPtr,
    capsule: CapsulePtr,
    verifying_pk: PublicKeyPtr,
    delegating_pk: PublicKeyPtr,
    receiving_pk: PublicKeyPtr,
    verified_cfrag_out: *mut VerifiedCapsuleFragPtr,
    error_out: *mut UmbralError,
) -> i32 {
    if cfrag.is_null()
        || capsule.is_null()
        || verifying_pk.is_null()
        || delegating_pk.is_null()
        || receiving_pk.is_null()
        || verified_cfrag_out.is_null()
    {
        if !error_out.is_null() {
            unsafe {
                *error_out = UmbralError::from_string(-1, "Null pointer passed".into());
            }
        }
        return -1;
    }

    unsafe {
        match (*cfrag)
            .clone()
            .verify(&*capsule, &*verifying_pk, &*delegating_pk, &*receiving_pk)
        {
            Ok(verified) => {
                *verified_cfrag_out = Box::into_raw(Box::new(verified));
                if !error_out.is_null() {
                    *error_out = UmbralError::success();
                }
                0
            }
            Err(e) => {
                if !error_out.is_null() {
                    *error_out = UmbralError::from_string(-5, alloc::format!("{:?}", e));
                }
                -5
            }
        }
    }
}

// ============================================================================
// Capsule seed key extraction
// ============================================================================

#[no_mangle]
pub extern "C" fn umbral_capsule_open_reencrypted(
    receiving_sk: SecretKeyPtr,
    delegating_pk: PublicKeyPtr,
    capsule: CapsulePtr,
    verified_cfrags: *const VerifiedCapsuleFragPtr,
    verified_cfrags_len: usize,
    key_seed_out: *mut ByteBuffer,
    error_out: *mut UmbralError,
) -> i32 {
    if receiving_sk.is_null()
        || delegating_pk.is_null()
        || capsule.is_null()
        || verified_cfrags.is_null()
        || key_seed_out.is_null()
    {
        if !error_out.is_null() {
            unsafe {
                *error_out = UmbralError::from_string(-1, "Null pointer passed".into());
            }
        }
        return -1;
    }

    unsafe {
        let cfrag_slice = slice::from_raw_parts(verified_cfrags, verified_cfrags_len);
        let cfrags: Vec<CapsuleFrag> = cfrag_slice
            .iter()
            .map(|&ptr| (*ptr).clone().unverify())
            .collect();

        match (*capsule).open_reencrypted(&*receiving_sk, &*delegating_pk, &cfrags) {
            Ok(key_seed) => {
                *key_seed_out =
                    ByteBuffer::from_boxed_slice(key_seed.as_secret().to_vec().into_boxed_slice());
                if !error_out.is_null() {
                    *error_out = UmbralError::success();
                }
                0
            }
            Err(e) => {
                if !error_out.is_null() {
                    *error_out = UmbralError::from_string(-6, alloc::format!("{:?}", e));
                }
                -6
            }
        }
    }
}

// ============================================================================
// Decrypt re-encrypted
// ============================================================================

#[no_mangle]
pub extern "C" fn umbral_decrypt_reencrypted(
    receiving_sk: SecretKeyPtr,
    delegating_pk: PublicKeyPtr,
    capsule: CapsulePtr,
    verified_cfrags: *const VerifiedCapsuleFragPtr,
    verified_cfrags_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    plaintext_out: *mut ByteBuffer,
    error_out: *mut UmbralError,
) -> i32 {
    if receiving_sk.is_null()
        || delegating_pk.is_null()
        || capsule.is_null()
        || verified_cfrags.is_null()
        || ciphertext.is_null()
        || plaintext_out.is_null()
    {
        if !error_out.is_null() {
            unsafe {
                *error_out = UmbralError::from_string(-1, "Null pointer passed".into());
            }
        }
        return -1;
    }

    unsafe {
        let cfrag_slice = slice::from_raw_parts(verified_cfrags, verified_cfrags_len);
        let cfrags: Vec<VerifiedCapsuleFrag> =
            cfrag_slice.iter().map(|&ptr| (*ptr).clone()).collect();
        let ciphertext_slice = slice::from_raw_parts(ciphertext, ciphertext_len);

        match decrypt_reencrypted(
            &*receiving_sk,
            &*delegating_pk,
            &*capsule,
            cfrags,
            ciphertext_slice,
        ) {
            Ok(plaintext) => {
                *plaintext_out = ByteBuffer::from_boxed_slice(plaintext);
                if !error_out.is_null() {
                    *error_out = UmbralError::success();
                }
                0
            }
            Err(e) => {
                if !error_out.is_null() {
                    *error_out = UmbralError::from_string(-6, alloc::format!("{:?}", e));
                }
                -6
            }
        }
    }
}

// ============================================================================
// DEM (Data Encryption Module) for symmetric encryption
// ============================================================================

#[no_mangle]
pub extern "C" fn umbral_dem_new(key_seed: *const u8, key_seed_len: usize) -> DEMPtr {
    if key_seed.is_null() || key_seed_len == 0 {
        return ptr::null_mut();
    }

    unsafe {
        let seed_slice = slice::from_raw_parts(key_seed, key_seed_len);
        let dem = DEM::new(seed_slice);
        Box::into_raw(Box::new(dem))
    }
}

#[no_mangle]
pub extern "C" fn umbral_dem_free(dem: DEMPtr) {
    if !dem.is_null() {
        unsafe {
            let _ = Box::from_raw(dem);
        }
    }
}

#[no_mangle]
pub extern "C" fn umbral_dem_decrypt(
    dem: DEMPtr,
    ciphertext: *const u8,
    ciphertext_len: usize,
    authenticated_data: *const u8,
    authenticated_data_len: usize,
    plaintext_out: *mut ByteBuffer,
    error_out: *mut UmbralError,
) -> i32 {
    if dem.is_null() || ciphertext.is_null() || plaintext_out.is_null() {
        if !error_out.is_null() {
            unsafe {
                *error_out = UmbralError::from_string(-1, "Null pointer passed".into());
            }
        }
        return -1;
    }

    unsafe {
        let ciphertext_slice = slice::from_raw_parts(ciphertext, ciphertext_len);
        let aad_slice = if authenticated_data.is_null() {
            &[]
        } else {
            slice::from_raw_parts(authenticated_data, authenticated_data_len)
        };

        match (*dem).decrypt(ciphertext_slice, aad_slice) {
            Ok(plaintext) => {
                *plaintext_out = ByteBuffer::from_boxed_slice(plaintext);
                if !error_out.is_null() {
                    *error_out = UmbralError::success();
                }
                0
            }
            Err(e) => {
                if !error_out.is_null() {
                    *error_out = UmbralError::from_string(-7, alloc::format!("{:?}", e));
                }
                -7
            }
        }
    }
}
