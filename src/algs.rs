use crate::keys;
use aes::{Aes128, Aes192, Aes256};
use aes_kw::{Kek, KekAes128, KekAes192, KekAes256};
use getrandom::getrandom;
use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};
use wasm_bindgen::prelude::*;

pub(crate) const ES256: i32 = -7;
pub(crate) const ES384: i32 = -35;
pub(crate) const ES512: i32 = -36;
pub(crate) const EDDSA: i32 = -8;
pub(crate) const SIGNING_ALGS: [i32; 4] = [ES256, ES384, ES512, EDDSA];
pub(crate) const SIGNING_ALGS_NAMES: [&str; 4] = ["ES256", "ES384", "ES512", "EDDSA"];

pub(crate) const A128GCM: i32 = 1;
pub(crate) const A192GCM: i32 = 2;
pub(crate) const A256GCM: i32 = 3;
pub(crate) const CHACHA20: i32 = 24;
pub(crate) const AES_CCM_16_64_128: i32 = 10;
pub(crate) const AES_CCM_16_64_256: i32 = 11;
pub(crate) const AES_CCM_64_64_128: i32 = 12;
pub(crate) const AES_CCM_64_64_256: i32 = 13;
pub(crate) const AES_CCM_16_128_128: i32 = 30;
pub(crate) const AES_CCM_16_128_256: i32 = 31;
pub(crate) const AES_CCM_64_128_128: i32 = 32;
pub(crate) const AES_CCM_64_128_256: i32 = 33;
pub(crate) const ENCRYPT_ALGS: [i32; 12] = [
    A128GCM,
    A192GCM,
    A256GCM,
    CHACHA20,
    AES_CCM_16_64_128,
    AES_CCM_16_64_256,
    AES_CCM_64_64_128,
    AES_CCM_64_64_256,
    AES_CCM_16_128_128,
    AES_CCM_16_128_256,
    AES_CCM_64_128_128,
    AES_CCM_64_128_256,
];
pub(crate) const ENCRYPT_ALGS_NAMES: [&str; 12] = [
    "A128GCM",
    "A192GCM",
    "A256GCM",
    "ChaCha20/Poly1305",
    "AES-CCM-16-64-128",
    "AES-CCM-16-64-256",
    "AES-CCM-64-64-128",
    "AES-CCM-64-64-256",
    "AES-CCM-16-128-128",
    "AES-CCM-16-128-256",
    "AES-CCM-64-128-128",
    "AES-CCM-64-128-256",
];

pub(crate) const HMAC_256_64: i32 = 4;
pub(crate) const HMAC_256_256: i32 = 5;
pub(crate) const HMAC_384_384: i32 = 6;
pub(crate) const HMAC_512_512: i32 = 7;
pub(crate) const AES_MAC_128_64: i32 = 14;
pub(crate) const AES_MAC_256_64: i32 = 15;
pub(crate) const AES_MAC_128_128: i32 = 25;
pub(crate) const AES_MAC_256_128: i32 = 26;
pub(crate) const MAC_ALGS_NAMES: [&str; 8] = [
    "HMAC 256/64",
    "HMAC 256/256",
    "HMAC 384/384",
    "HMAC 512/512",
    "AES-MAC 128/64",
    "AES-MAC 256/64",
    "AES-MAC 128/128",
    "AES-MAC 256/128",
];
pub(crate) const MAC_ALGS: [i32; 8] = [
    HMAC_256_64,
    HMAC_256_256,
    HMAC_384_384,
    HMAC_512_512,
    AES_MAC_128_64,
    AES_MAC_256_64,
    AES_MAC_128_128,
    AES_MAC_256_128,
];

pub(crate) const DIRECT: i32 = -6;
pub(crate) const DIRECT_HKDF_SHA_256: i32 = -10;
pub(crate) const DIRECT_HKDF_SHA_512: i32 = -11;
pub(crate) const DIRECT_HKDF_AES_128: i32 = -12;
pub(crate) const DIRECT_HKDF_AES_256: i32 = -13;
pub(crate) const A128KW: i32 = -3;
pub(crate) const A192KW: i32 = -4;
pub(crate) const A256KW: i32 = -5;
pub(crate) const ECDH_ES_HKDF_256: i32 = -25;
pub(crate) const ECDH_ES_HKDF_512: i32 = -26;
pub(crate) const ECDH_SS_HKDF_256: i32 = -27;
pub(crate) const ECDH_SS_HKDF_512: i32 = -28;
pub(crate) const ECDH_ES_A128KW: i32 = -29;
pub(crate) const ECDH_ES_A192KW: i32 = -30;
pub(crate) const ECDH_ES_A256KW: i32 = -31;
pub(crate) const ECDH_SS_A128KW: i32 = -32;
pub(crate) const ECDH_SS_A192KW: i32 = -33;
pub(crate) const ECDH_SS_A256KW: i32 = -34;
pub(crate) const KEY_DISTRIBUTION_ALGS: [i32; 18] = [
    DIRECT,
    DIRECT_HKDF_SHA_256,
    DIRECT_HKDF_SHA_512,
    DIRECT_HKDF_AES_128,
    DIRECT_HKDF_AES_256,
    A128KW,
    A192KW,
    A256KW,
    ECDH_ES_HKDF_256,
    ECDH_ES_HKDF_512,
    ECDH_SS_HKDF_256,
    ECDH_SS_HKDF_512,
    ECDH_ES_A128KW,
    ECDH_ES_A192KW,
    ECDH_ES_A256KW,
    ECDH_SS_A128KW,
    ECDH_SS_A192KW,
    ECDH_SS_A256KW,
];
pub(crate) const KEY_DISTRIBUTION_NAMES: [&str; 18] = [
    "direct",
    "direct+HKDF-SHA-256",
    "direct+HKDF-SHA-512",
    "direct+HKDF-AES-128",
    "direct+HKDF-AES-256",
    "A128KW",
    "A192KW",
    "A256KW",
    "ECDH-ES + HKDF-256",
    "ECDH-ES + HKDF-512",
    "ECDH-SS + HKDF-256",
    "ECDH-SS + HKDF-512",
    "ECDH-ES + A128KW",
    "ECDH-ES + A192KW",
    "ECDH-ES + A256KW",
    "ECDH-SS + A128KW",
    "ECDH-SS + A192KW",
    "ECDH-SS + A256KW",
];
pub(crate) const ECDH_ALGS: [i32; 10] = [
    ECDH_ES_HKDF_256,
    ECDH_ES_HKDF_512,
    ECDH_SS_HKDF_256,
    ECDH_SS_HKDF_512,
    ECDH_ES_A128KW,
    ECDH_ES_A192KW,
    ECDH_ES_A256KW,
    ECDH_SS_A128KW,
    ECDH_SS_A192KW,
    ECDH_SS_A256KW,
];

const K32_ALGS: [i32; 12] = [
    A256GCM,
    AES_CCM_16_64_256,
    AES_CCM_64_64_256,
    AES_CCM_16_128_256,
    AES_CCM_64_128_256,
    AES_MAC_256_128,
    AES_MAC_256_64,
    HMAC_256_256,
    HMAC_256_64,
    ECDH_ES_A256KW,
    ECDH_SS_A256KW,
    A256KW,
];
const K24_ALGS: [i32; 4] = [ECDH_ES_A192KW, ECDH_SS_A192KW, A192GCM, A128KW];

const K16_ALGS: [i32; 11] = [
    A128GCM,
    CHACHA20,
    AES_CCM_16_64_128,
    AES_CCM_64_64_128,
    AES_CCM_16_128_128,
    AES_CCM_64_128_128,
    AES_MAC_128_64,
    AES_MAC_128_128,
    ECDH_ES_A128KW,
    ECDH_SS_A128KW,
    A192KW,
];

pub(crate) const OKP_ALGS: [i32; 1] = [EDDSA];
pub(crate) const EC2_ALGS: [i32; 3] = [ES256, ES384, ES512];
pub(crate) const SYMMETRIC_ALGS: [i32; 28] = [
    A128GCM,
    A192GCM,
    A256GCM,
    CHACHA20,
    AES_CCM_16_64_128,
    AES_CCM_16_64_256,
    AES_CCM_64_64_128,
    AES_CCM_64_64_256,
    AES_CCM_16_128_128,
    AES_CCM_16_128_256,
    AES_CCM_64_128_128,
    AES_CCM_64_128_256,
    HMAC_256_64,
    HMAC_256_256,
    HMAC_384_384,
    HMAC_512_512,
    AES_MAC_128_64,
    AES_MAC_256_64,
    AES_MAC_128_128,
    AES_MAC_256_128,
    DIRECT,
    DIRECT_HKDF_SHA_256,
    DIRECT_HKDF_SHA_512,
    DIRECT_HKDF_AES_128,
    DIRECT_HKDF_AES_256,
    A128KW,
    A192KW,
    A256KW,
];
pub(crate) const A_KW: [i32; 3] = [A128KW, A192KW, A256KW];
pub(crate) const D_HA: [i32; 2] = [DIRECT_HKDF_AES_128, DIRECT_HKDF_AES_256];
pub(crate) const D_HS: [i32; 2] = [DIRECT_HKDF_SHA_256, DIRECT_HKDF_SHA_512];
pub(crate) const ECDH_H: [i32; 4] = [
    ECDH_ES_HKDF_256,
    ECDH_ES_HKDF_512,
    ECDH_SS_HKDF_256,
    ECDH_SS_HKDF_512,
];
pub(crate) const ECDH_A: [i32; 6] = [
    ECDH_ES_A128KW,
    ECDH_ES_A192KW,
    ECDH_ES_A256KW,
    ECDH_SS_A128KW,
    ECDH_SS_A192KW,
    ECDH_SS_A256KW,
];

pub(crate) fn sign(alg: i32, key: &Vec<u8>, content: &Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let s: Vec<u8>;
    if alg == EDDSA {
        use ed25519_compact::SecretKey;
        let priv_key = match SecretKey::from_der(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid EdDSA Private Key")),
        };
        let signature = priv_key.sign(&content, None);
        s = signature.as_slice().to_vec();
    } else if alg == ES256 {
        use p256::ecdsa::{signature::Signer, SigningKey};
        let priv_key = match SigningKey::from_bytes(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid ECDSA Private Key")),
        };
        s = priv_key.sign(&content).to_vec();
    } else if alg == ES384 {
        use p384::ecdsa::{signature::Signer, SigningKey};
        let priv_key = match SigningKey::from_bytes(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid ECDSA Private Key")),
        };
        s = priv_key.sign(&content).to_vec();
    } else if alg == ES512 {
        return Err(JsValue::from("ES512 not implemented"));
    } else {
        return Err(JsValue::from("Invalid Algorithm"));
    }
    Ok(s)
}

pub(crate) fn verify(
    alg: i32,
    key: &Vec<u8>,
    content: &Vec<u8>,
    signature: &Vec<u8>,
) -> Result<bool, JsValue> {
    let v: bool;
    if alg == EDDSA {
        use ed25519_compact::{PublicKey, Signature};
        let ec_public_key = match PublicKey::from_der(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid EdDSA Public Key")),
        };
        let sig = match Signature::from_slice(&signature) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid Signature")),
        };
        v = ec_public_key.verify(&content, &sig).is_ok();
    } else if alg == ES256 {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let pub_key = match VerifyingKey::from_sec1_bytes(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid ECDSA Public Key")),
        };
        let signature: Signature = match Signature::try_from(signature.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid Signature")),
        };
        v = pub_key.verify(&content, &signature).is_ok();
    } else if alg == ES384 {
        use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let pub_key = match VerifyingKey::from_sec1_bytes(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid ECDSA Public Key")),
        };
        let signature: Signature = match Signature::try_from(signature.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid Signature")),
        };
        v = pub_key.verify(&content, &signature).is_ok();
    } else if alg == ES512 {
        return Err(JsValue::from("ES512 not implemnented"));
    } else {
        return Err(JsValue::from("Invalid Algorithm"));
    }
    Ok(v)
}

pub(crate) fn mac(alg: i32, key: &Vec<u8>, content: &Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let mut message_digest;
    let size;
    if alg == HMAC_256_64 {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = match HmacSha256::new_from_slice(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        message_digest = mac.finalize().into_bytes().to_vec();
        size = 8;
    } else if alg == HMAC_256_256 {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = match HmacSha256::new_from_slice(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        message_digest = mac.finalize().into_bytes().to_vec();
        size = 32;
    } else if alg == HMAC_384_384 {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha384>;
        let mut mac = match HmacSha256::new_from_slice(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        message_digest = mac.finalize().into_bytes().to_vec();
        size = 48;
    } else if alg == HMAC_512_512 {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha512>;
        let mut mac = match HmacSha256::new_from_slice(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        message_digest = mac.finalize().into_bytes().to_vec();
        size = 64;
    } else if alg == AES_MAC_128_64 {
        use cbc_mac::{CbcMac, Mac};
        type Daa = CbcMac<Aes128>;
        let mut mac = match Daa::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        size = 8;
        message_digest = mac.finalize().into_bytes().to_vec();
    } else if alg == AES_MAC_256_64 {
        use cbc_mac::{CbcMac, Mac};
        type Daa = CbcMac<Aes256>;
        let mut mac = match Daa::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        size = 8;
        message_digest = mac.finalize().into_bytes().to_vec();
    } else if alg == AES_MAC_128_128 {
        use cbc_mac::{CbcMac, Mac};
        type Daa = CbcMac<Aes128>;
        let mut mac = match Daa::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        size = 16;
        message_digest = mac.finalize().into_bytes().to_vec();
    } else if alg == AES_MAC_256_128 {
        use cbc_mac::{CbcMac, Mac};
        type Daa = CbcMac<Aes256>;
        let mut mac = match Daa::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        size = 16;
        message_digest = mac.finalize().into_bytes().to_vec();
    } else {
        return Err(JsValue::from("Invalid Algorithm"));
    }
    message_digest.truncate(size);
    Ok(message_digest)
}

pub(crate) fn mac_verify(
    alg: i32,
    key: &Vec<u8>,
    content: &Vec<u8>,
    signature: &Vec<u8>,
) -> Result<bool, JsValue> {
    let mut message_digest;
    let size;
    if alg == HMAC_256_64 {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = match HmacSha256::new_from_slice(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        message_digest = mac.finalize().into_bytes().to_vec();
        size = 8;
    } else if alg == HMAC_256_256 {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = match HmacSha256::new_from_slice(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };

        mac.update(&content);
        message_digest = mac.finalize().into_bytes().to_vec();
        size = 32;
    } else if alg == HMAC_384_384 {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha384>;
        let mut mac = match HmacSha256::new_from_slice(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        message_digest = mac.finalize().into_bytes().to_vec();
        size = 48;
    } else if alg == HMAC_512_512 {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha512>;
        let mut mac = match HmacSha256::new_from_slice(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        message_digest = mac.finalize().into_bytes().to_vec();
        size = 64;
    } else if alg == AES_MAC_128_64 {
        use cbc_mac::{CbcMac, Mac};
        type Daa = CbcMac<Aes128>;
        let mut mac = match Daa::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        size = 8;
        message_digest = mac.finalize().into_bytes().to_vec();
    } else if alg == AES_MAC_256_64 {
        use cbc_mac::{CbcMac, Mac};
        type Daa = CbcMac<Aes256>;
        let mut mac = match Daa::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        size = 8;
        message_digest = mac.finalize().into_bytes().to_vec();
    } else if alg == AES_MAC_128_128 {
        use cbc_mac::{CbcMac, Mac};
        type Daa = CbcMac<Aes128>;
        let mut mac = match Daa::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        size = 16;
        message_digest = mac.finalize().into_bytes().to_vec();
    } else if alg == AES_MAC_256_128 {
        use cbc_mac::{CbcMac, Mac};
        type Daa = CbcMac<Aes256>;
        let mut mac = match Daa::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        size = 16;
        message_digest = mac.finalize().into_bytes().to_vec();
    } else {
        return Err(JsValue::from("Invalid Algorithm"));
    }
    message_digest.truncate(size);
    Ok(&message_digest == signature)
}
pub(crate) fn encrypt(
    alg: i32,
    key: &Vec<u8>,
    iv: &Vec<u8>,
    payload: &Vec<u8>,
    aead: &Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let mut c = payload.to_vec();
    if alg == A128GCM {
        use aes_gcm::{
            aead::{AeadInPlace, KeyInit},
            Aes128Gcm, Nonce,
        };
        let cipher = match Aes128Gcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES-GCM Key")),
        };
        let nonce = Nonce::from_slice(iv);
        match cipher.encrypt_in_place(&nonce, aead, &mut c) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during encryption")),
        }
    } else if alg == A192GCM {
        use aes_gcm::{
            aead::{
                generic_array::{typenum, GenericArray},
                AeadInPlace, KeyInit,
            },
            AesGcm, Nonce,
        };

        let cipher: AesGcm<Aes192, typenum::U12> = AesGcm::new(GenericArray::from_slice(&key));
        let nonce = Nonce::from_slice(iv);
        match cipher.encrypt_in_place(&nonce, aead, &mut c) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during encryption")),
        }
    } else if alg == A256GCM {
        use aes_gcm::{
            aead::{AeadInPlace, KeyInit},
            Aes256Gcm, Nonce,
        };

        let cipher = match Aes256Gcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES-GCM Key")),
        };
        let nonce = Nonce::from_slice(iv);
        match cipher.encrypt_in_place(&nonce, aead, &mut c) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during encryption")),
        }
    } else if alg == CHACHA20 {
        use chacha20poly1305::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            ChaCha20Poly1305,
        };
        let cipher = match ChaCha20Poly1305::new_from_slice(key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid ChaCha20Poly1305 Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.encrypt_in_place(&nonce, aead, &mut c) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during encryption")),
        }
    } else if alg == AES_CCM_16_64_128 {
        use ccm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            consts::{U13, U8},
            Ccm,
        };
        type AesCcm = Ccm<Aes128, U8, U13>;
        let cipher = match AesCcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES CCM Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.encrypt_in_place(&nonce, aead, &mut c) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Error during encryption")),
        };
    } else if alg == AES_CCM_16_64_256 {
        use ccm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            consts::{U13, U8},
            Ccm,
        };
        type AesCcm = Ccm<Aes256, U8, U13>;
        let cipher = match AesCcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES CCM Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.encrypt_in_place(&nonce, aead, &mut c) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Error during encryption")),
        };
    } else if alg == AES_CCM_64_64_128 {
        use ccm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            consts::{U7, U8},
            Ccm,
        };
        type AesCcm = Ccm<Aes128, U8, U7>;
        let cipher = match AesCcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES CCM Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.encrypt_in_place(&nonce, aead, &mut c) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Error during encryption")),
        };
    } else if alg == AES_CCM_64_64_256 {
        use ccm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            consts::{U7, U8},
            Ccm,
        };
        type AesCcm = Ccm<Aes256, U8, U7>;
        let cipher = match AesCcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES CCM Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.encrypt_in_place(&nonce, aead, &mut c) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Error during encryption")),
        };
    } else if alg == AES_CCM_16_128_128 {
        use ccm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            consts::{U13, U16},
            Ccm,
        };
        type AesCcm = Ccm<Aes128, U16, U13>;
        let cipher = match AesCcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES CCM Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.encrypt_in_place(&nonce, aead, &mut c) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Error during encryption")),
        };
    } else if alg == AES_CCM_16_128_256 {
        use ccm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            consts::{U13, U16},
            Ccm,
        };
        type AesCcm = Ccm<Aes256, U16, U13>;
        let cipher = match AesCcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES CCM Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.encrypt_in_place(&nonce, aead, &mut c) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Error during encryption")),
        };
    } else if alg == AES_CCM_64_128_128 {
        use ccm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            consts::{U16, U7},
            Ccm,
        };
        type AesCcm = Ccm<Aes128, U16, U7>;
        let cipher = match AesCcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES CCM Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.encrypt_in_place(&nonce, aead, &mut c) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Error during encryption")),
        };
    } else if alg == AES_CCM_64_128_256 {
        use ccm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            consts::{U16, U7},
            Ccm,
        };
        type AesCcm = Ccm<Aes256, U16, U7>;
        let cipher = match AesCcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES CCM Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.encrypt_in_place(&nonce, aead, &mut c) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Error during encryption")),
        };
    } else {
        return Err(JsValue::from("Invalid Algorithm"));
    }
    Ok(c)
}

pub(crate) fn decrypt(
    alg: i32,
    key: &Vec<u8>,
    iv: &Vec<u8>,
    ciphertext: &Vec<u8>,
    aead: &Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let mut c = ciphertext.to_vec();
    if alg == A128GCM {
        use aes_gcm::{
            aead::{AeadInPlace, KeyInit},
            Aes128Gcm, Nonce,
        };

        let cipher = match Aes128Gcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES-GCM Key")),
        };
        let nonce = Nonce::from_slice(iv);
        match cipher.decrypt_in_place(&nonce, aead, &mut c) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Error during decrypt")),
        };
    } else if alg == A192GCM {
        use aes_gcm::{
            aead::{
                generic_array::{typenum, GenericArray},
                AeadInPlace, KeyInit,
            },
            AesGcm, Nonce,
        };

        let cipher: AesGcm<Aes192, typenum::U12> = AesGcm::new(GenericArray::from_slice(&key));
        let nonce = Nonce::from_slice(iv);
        match cipher.decrypt_in_place(&nonce, aead, &mut c) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during decrypt")),
        };
    } else if alg == A256GCM {
        use aes_gcm::{
            aead::{AeadInPlace, KeyInit},
            Aes256Gcm, Nonce,
        };

        let cipher = match Aes256Gcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES-GCM Key")),
        };
        let nonce = Nonce::from_slice(iv);
        match cipher.decrypt_in_place(&nonce, aead, &mut c) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during decrypt")),
        };
    } else if alg == CHACHA20 {
        use chacha20poly1305::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            ChaCha20Poly1305,
        };
        let cipher = match ChaCha20Poly1305::new_from_slice(key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid ChaCha20Poly1305 Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.decrypt_in_place(&nonce, aead, &mut c) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during decrypt")),
        };
    } else if alg == AES_CCM_16_64_128 {
        use ccm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            consts::{U13, U8},
            Ccm,
        };
        type AesCcm = Ccm<Aes128, U8, U13>;
        let cipher = match AesCcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES CCM Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.decrypt_in_place(&nonce, aead, &mut c) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during decrypt")),
        };
    } else if alg == AES_CCM_16_64_256 {
        use ccm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            consts::{U13, U8},
            Ccm,
        };
        type AesCcm = Ccm<Aes256, U8, U13>;
        let cipher = match AesCcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES CCM Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.decrypt_in_place(&nonce, aead, &mut c) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during decrypt")),
        };
    } else if alg == AES_CCM_64_64_128 {
        use ccm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            consts::{U7, U8},
            Ccm,
        };
        type AesCcm = Ccm<Aes128, U8, U7>;
        let cipher = match AesCcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES CCM Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.decrypt_in_place(&nonce, aead, &mut c) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during decrypt")),
        };
    } else if alg == AES_CCM_64_64_256 {
        use ccm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            consts::{U7, U8},
            Ccm,
        };
        type AesCcm = Ccm<Aes256, U8, U7>;
        let cipher = match AesCcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES CCM Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.decrypt_in_place(&nonce, aead, &mut c) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during decrypt")),
        };
    } else if alg == AES_CCM_16_128_128 {
        use ccm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            consts::{U13, U16},
            Ccm,
        };
        type AesCcm = Ccm<Aes128, U16, U13>;
        let cipher = match AesCcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES CCM Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.decrypt_in_place(&nonce, aead, &mut c) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during decrypt")),
        };
    } else if alg == AES_CCM_16_128_256 {
        use ccm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            consts::{U13, U16},
            Ccm,
        };
        type AesCcm = Ccm<Aes256, U16, U13>;
        let cipher = match AesCcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES CCM Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.decrypt_in_place(&nonce, aead, &mut c) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during decrypt")),
        };
    } else if alg == AES_CCM_64_128_128 {
        use ccm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            consts::{U16, U7},
            Ccm,
        };
        type AesCcm = Ccm<Aes128, U16, U7>;
        let cipher = match AesCcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES CCM Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.decrypt_in_place(&nonce, aead, &mut c) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during decrypt")),
        };
    } else if alg == AES_CCM_64_128_256 {
        use ccm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            consts::{U16, U7},
            Ccm,
        };
        type AesCcm = Ccm<Aes256, U16, U7>;
        let cipher = match AesCcm::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES CCM Key")),
        };
        let nonce = GenericArray::from_slice(iv);
        match cipher.decrypt_in_place(&nonce, aead, &mut c) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during decrypt")),
        };
    } else {
        return Err(JsValue::from("Invalid Algorithm"));
    }

    Ok(c)
}

pub(crate) fn aes_key_wrap(key: &Vec<u8>, alg: i32, cek: &Vec<u8>) -> Result<Vec<u8>, JsValue> {
    if alg == A128KW {
        let kek: KekAes128 = match Kek::try_from(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES-KW Key")),
        };
        match kek.wrap_vec(cek) {
            Ok(v) => Ok(v),
            Err(_) => return Err(JsValue::from("Error during Key Wrap")),
        }
    } else if alg == A192KW {
        let kek: KekAes192 = match Kek::try_from(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES-KW Key")),
        };
        match kek.wrap_vec(cek) {
            Ok(v) => Ok(v),
            Err(_) => return Err(JsValue::from("Error during Key Wrap")),
        }
    } else if alg == A256KW {
        let kek: KekAes256 = match Kek::try_from(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES-KW Key")),
        };
        match kek.wrap_vec(cek) {
            Ok(v) => Ok(v),
            Err(_) => return Err(JsValue::from("Error during Key Wrap")),
        }
    } else {
        return Err(JsValue::from("Invalid KEK size"));
    }
}

pub(crate) fn aes_key_unwrap(key: &Vec<u8>, alg: i32, cek: &Vec<u8>) -> Result<Vec<u8>, JsValue> {
    if alg == A128KW {
        let kek: KekAes128 = match Kek::try_from(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES-KW Key")),
        };
        match kek.unwrap_vec(cek) {
            Ok(v) => Ok(v),
            Err(_) => return Err(JsValue::from("Error during Key Unwrap")),
        }
    } else if alg == A192KW {
        let kek: KekAes192 = match Kek::try_from(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES-KW Key")),
        };
        match kek.unwrap_vec(cek) {
            Ok(v) => Ok(v),
            Err(_) => return Err(JsValue::from("Error during Key Unwrap")),
        }
    } else if alg == A256KW {
        let kek: KekAes256 = match Kek::try_from(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid AES-KW Key")),
        };
        match kek.unwrap_vec(cek) {
            Ok(v) => Ok(v),
            Err(_) => return Err(JsValue::from("Error during Key Unwrap")),
        }
    } else {
        return Err(JsValue::from("Invalid KEK size"));
    }
}

pub(crate) fn ecdh_derive_key(
    crv_rec: &i32,
    crv_send: &i32,
    receiver_key: &Vec<u8>,
    sender_key: &Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    if crv_rec != crv_send {
        return Err("Elliptic Curves don't match".into());
    } else if *crv_send == keys::P_256 {
        use p256::{ecdh, PublicKey, SecretKey};
        return Ok(ecdh::diffie_hellman(
            match SecretKey::from_be_bytes(&sender_key) {
                Ok(v) => v.to_nonzero_scalar(),
                Err(_) => return Err(JsValue::from("Invalid ECDH Private key")),
            },
            match PublicKey::from_sec1_bytes(&receiver_key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid ECDH Public Key")),
            }
            .as_affine(),
        )
        .raw_secret_bytes()
        .to_vec());
    } else if *crv_send == keys::P_384 {
        use p384::{ecdh, PublicKey, SecretKey};
        return Ok(ecdh::diffie_hellman(
            match SecretKey::from_be_bytes(&sender_key) {
                Ok(v) => v.to_nonzero_scalar(),
                Err(_) => return Err(JsValue::from("Invalid ECDH Private Key")),
            },
            match PublicKey::from_sec1_bytes(&receiver_key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid ECDH Public Key")),
            }
            .as_affine(),
        )
        .raw_secret_bytes()
        .to_vec());
    } else if *crv_send == keys::P_521 {
        return Err(JsValue::from("P_521 not implemented"));
    } else {
        return Err(JsValue::from("Invalid Curve"));
    }
}

pub(crate) fn hkdf(
    length: usize,
    ikm: &Vec<u8>,
    salt_input: Option<&Vec<u8>>,
    info_input: &mut Vec<u8>,
    alg: i32,
) -> Result<Vec<u8>, JsValue> {
    let salt = match salt_input {
        Some(v) => Some(v.as_slice()),
        None => None,
    };
    if [ECDH_ES_HKDF_512, ECDH_SS_HKDF_512, DIRECT_HKDF_SHA_512].contains(&alg) {
        let hk = Hkdf::<Sha512>::new(salt, &ikm);
        let mut okm = [0u8; 32];
        match hk.expand(&info_input, &mut okm) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during HKDF expand")),
        };
        return Ok(okm[..length as usize].to_vec());
    }
    let hk = Hkdf::<Sha256>::new(salt, &ikm);
    let mut okm = [0u8; 32];
    match hk.expand(&info_input, &mut okm) {
        Ok(_) => (),
        Err(_) => return Err(JsValue::from("Error during HKDF expand")),
    };
    return Ok(okm[..length as usize].to_vec());
}

pub(crate) fn get_cek_size(alg: &i32) -> Result<usize, JsValue> {
    if K16_ALGS.contains(alg) {
        Ok(16)
    } else if K32_ALGS.contains(alg) {
        Ok(32)
    } else if K24_ALGS.contains(alg) {
        Ok(24)
    } else if HMAC_384_384 == *alg {
        Ok(48)
    } else if HMAC_512_512 == *alg {
        Ok(64)
    } else {
        Err(JsValue::from("Invalid Algorithm"))
    }
}
pub(crate) fn gen_random_key(alg: &i32) -> Result<Vec<u8>, JsValue> {
    if K16_ALGS.contains(alg) {
        let mut value: [u8; 16] = [0; 16];
        match getrandom(&mut value) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error generating random key")),
        };
        Ok(value.to_vec())
    } else if K32_ALGS.contains(alg) {
        let mut value: [u8; 32] = [0; 32];
        match getrandom(&mut value) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error generating random key")),
        };
        Ok(value.to_vec())
    } else if K24_ALGS.contains(alg) {
        let mut value: [u8; 24] = [0; 24];
        match getrandom(&mut value) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error generating random key")),
        };
        Ok(value.to_vec())
    } else if HMAC_384_384 == *alg {
        let mut value: [u8; 48] = [0; 48];
        match getrandom(&mut value) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error generating random key")),
        };
        Ok(value.to_vec())
    } else if HMAC_512_512 == *alg {
        let mut value: [u8; 64] = [0; 64];
        match getrandom(&mut value) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error generating random key")),
        };
        Ok(value.to_vec())
    } else {
        Err(JsValue::from("Invalid Algorithm"))
    }
}

pub(crate) fn gen_iv(partial_iv: &mut Vec<u8>, base_iv: &Vec<u8>) -> Vec<u8> {
    let mut left_padded = vec![0; base_iv.len() - partial_iv.len()];
    left_padded.append(partial_iv);
    let mut iv = Vec::new();
    for i in 0..left_padded.len() {
        iv.push(left_padded[i] ^ base_iv[i]);
    }
    iv
}
