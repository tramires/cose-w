use crate::keys;

use aes::{Aes128, Aes192, Aes256};
use aes_kw::{Kek, KekAes128, KekAes192, KekAes256};
use cbc_mac::{CbcMac, Mac};
use getrandom::getrandom;
use hkdf::Hkdf;
use hmac::Hmac;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use wasm_bindgen::prelude::*;

type Daa128 = CbcMac<Aes128>;
type Daa256 = CbcMac<Aes256>;

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

pub(crate) const ES256: i32 = -7;
pub(crate) const ES256K: i32 = -47;
pub(crate) const ES384: i32 = -35;
pub(crate) const ES512: i32 = -36;
pub(crate) const EDDSA: i32 = -8;
pub(crate) const PS512: i32 = -39;
pub(crate) const PS384: i32 = -38;
pub(crate) const PS256: i32 = -37;
pub(crate) const SIGNING_ALGS: [i32; 8] = [ES256, ES384, ES512, EDDSA, PS256, PS384, PS512, ES256K];
pub(crate) const SIGNING_ALGS_NAMES: [&str; 8] = [
    "ES256", "ES384", "ES512", "EDDSA", "PS256", "PS384", "PS512", "ES256K",
];

pub(crate) const SHA_256: i32 = -16;

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
pub(crate) const RSA_OAEP_1: i32 = -40;
pub(crate) const RSA_OAEP_256: i32 = -41;
pub(crate) const RSA_OAEP_512: i32 = -42;
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
pub(crate) const KEY_DISTRIBUTION_ALGS: [i32; 21] = [
    DIRECT,
    DIRECT_HKDF_SHA_256,
    DIRECT_HKDF_SHA_512,
    DIRECT_HKDF_AES_128,
    DIRECT_HKDF_AES_256,
    A128KW,
    A192KW,
    A256KW,
    RSA_OAEP_1,
    RSA_OAEP_256,
    RSA_OAEP_512,
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
pub(crate) const KEY_DISTRIBUTION_NAMES: [&str; 21] = [
    "direct",
    "direct+HKDF-SHA-256",
    "direct+HKDF-SHA-512",
    "direct+HKDF-AES-128",
    "direct+HKDF-AES-256",
    "A128KW",
    "A192KW",
    "A256KW",
    "RSAES-OAEP w/ RFC 8017 default parameters",
    "RSAES-OAEP w/ SHA-256",
    "RSAES-OAEP w/ SHA-512",
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

pub(crate) const OAEP_ALGS: [i32; 3] = [RSA_OAEP_1, RSA_OAEP_256, RSA_OAEP_512];

pub(crate) const HKDF_ALGS: [i32; 14] = [
    DIRECT_HKDF_SHA_256,
    DIRECT_HKDF_SHA_512,
    DIRECT_HKDF_AES_128,
    DIRECT_HKDF_AES_256,
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
    A128KW,
];
const K24_ALGS: [i32; 4] = [A192KW, ECDH_ES_A192KW, ECDH_SS_A192KW, A192GCM];
const K32_ALGS: [i32; 12] = [
    A256GCM,
    AES_CCM_16_64_256,
    AES_CCM_64_64_256,
    AES_CCM_16_128_256,
    AES_CCM_64_128_256,
    AES_MAC_256_128,
    AES_MAC_256_64,
    HMAC_256_64,
    HMAC_256_256,
    ECDH_ES_A256KW,
    ECDH_SS_A256KW,
    A256KW,
];

const DER_S2: [u8; 16] = [48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32];
const DER_P2: [u8; 12] = [48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0];

pub(crate) const RSA_OAEP: [i32; 3] = [RSA_OAEP_1, RSA_OAEP_256, RSA_OAEP_512];
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

pub(crate) fn sign(
    alg: i32,
    crv: Option<i32>,
    key: &Vec<u8>,
    content: &Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let s: Vec<u8>;
    match alg {
        EDDSA => {
            let crv = crv.ok_or(JsValue::from("Missing curve"))?;
            use ed25519_compact::SecretKey;
            let mut ed_key;
            if crv == keys::ED25519 {
                ed_key = DER_S2.to_vec();
                ed_key.append(&mut key.clone());
            } else if crv == keys::ED448 {
                return Err(JsValue::from("Ed448 not implemented"));
            } else {
                return Err(JsValue::from("Invalid curve"));
            }
            let priv_key = match SecretKey::from_der(&ed_key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid EDDSA private key")),
            };
            let signature = priv_key.sign(&content, None);
            s = signature.as_slice().to_vec();
        }
        ES256 => {
            let crv = crv.ok_or(JsValue::from("Missing curve"))?;
            use p256::ecdsa::{signature::Signer, SigningKey};
            if crv != keys::P_256 {
                return Err(JsValue::from("Invalid curve"));
            }
            let priv_key = match SigningKey::from_bytes(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid ES256 private key")),
            };
            s = priv_key.sign(&content).to_vec();
        }
        ES256K => {
            let crv = crv.ok_or(JsValue::from("Missing curve"))?;
            use k256::ecdsa::{signature::Signer, Signature, SigningKey};
            if crv != keys::SECP256K1 {
                return Err(JsValue::from("Invalid curve"));
            }
            let priv_key = match SigningKey::from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid E256K private key")),
            };
            let sig: Signature = priv_key.sign(&content);
            return Ok(sig.to_vec());
        }
        ES384 => {
            let crv = crv.ok_or(JsValue::from("Missing curve"))?;
            use p384::ecdsa::{signature::Signer, SigningKey};
            if crv != keys::P_384 {
                return Err(JsValue::from("Invalid curve"));
            }
            let priv_key = match SigningKey::from_bytes(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid ES384 private key")),
            };
            s = priv_key.sign(&content).to_vec();
        }
        ES512 => {
            let crv = crv.ok_or(JsValue::from("Missing curve"))?;
            if crv != keys::P_521 {
                return Err(JsValue::from("Invalid curve"));
            }
            return Err(JsValue::from("ES512 not implemented"));
        }
        PS256 | PS384 | PS512 => {
            use rsa::pkcs1::DecodeRsaPrivateKey;
            use rsa::pss::SigningKey;
            use rsa::signature::RandomizedSigner;
            use rsa::signature::SignatureEncoding;
            use rsa::RsaPrivateKey;
            let priv_key = match RsaPrivateKey::from_pkcs1_der(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid RSA private key")),
            };
            if alg == PS256 {
                let signing_key: SigningKey<Sha256> = SigningKey::new(priv_key);
                let mut rng = rand::thread_rng();
                s = signing_key.sign_with_rng(&mut rng, &content).to_vec();
            } else if alg == PS384 {
                let signing_key: SigningKey<Sha384> = SigningKey::new(priv_key);
                let mut rng = rand::thread_rng();
                s = signing_key.sign_with_rng(&mut rng, &content).to_vec();
            } else {
                let signing_key: SigningKey<Sha512> = SigningKey::new(priv_key);
                let mut rng = rand::thread_rng();
                s = signing_key.sign_with_rng(&mut rng, &content).to_vec();
            }
        }
        _ => {
            return Err(JsValue::from("Invalid algorithm"));
        }
    }
    Ok(s)
}

pub(crate) fn verify(
    alg: i32,
    crv: Option<i32>,
    key: &Vec<u8>,
    content: &Vec<u8>,
    signature: &Vec<u8>,
) -> Result<bool, JsValue> {
    let v: bool;
    match alg {
        EDDSA => {
            use ed25519_compact::{PublicKey, Signature};
            let mut ed_key;
            let crv = crv.ok_or(JsValue::from("Missing curve"))?;
            if crv == keys::ED25519 {
                ed_key = DER_P2.to_vec();
                ed_key.append(&mut key.clone());
            } else if crv == keys::ED448 {
                return Err(JsValue::from("Ed448 not implemented"));
            } else {
                return Err(JsValue::from("Invalid curve"));
            }
            let ec_public_key = match PublicKey::from_der(&ed_key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid EDDSA public key")),
            };
            let sig: Signature = match Signature::from_slice(&signature) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid signature")),
            };
            v = ec_public_key.verify(&content, &sig).is_ok();
        }
        ES256K => {
            use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let crv = crv.ok_or(JsValue::from("Missing curve"))?;
            if crv != keys::SECP256K1 {
                return Err(JsValue::from("Invalid curve"));
            }
            let pub_key = match VerifyingKey::from_sec1_bytes(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid ES256K public key")),
            };
            let signature: Signature = match Signature::try_from(signature.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid signature")),
            };
            v = pub_key.verify(content, &signature).is_ok();
        }
        ES256 => {
            use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let crv = crv.ok_or(JsValue::from("Missing curve"))?;
            if crv != keys::P_256 {
                return Err(JsValue::from("Invalid curve"));
            }
            let pub_key = match VerifyingKey::from_sec1_bytes(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid ES256 public key")),
            };
            let signature: Signature = match Signature::try_from(signature.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid signature")),
            };
            v = pub_key.verify(&content, &signature).is_ok();
        }
        ES384 => {
            use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let crv = crv.ok_or(JsValue::from("Invalid curve"))?;
            if crv != keys::P_384 {
                return Err(JsValue::from("Invalid curve"));
            }
            let pub_key = match VerifyingKey::from_sec1_bytes(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid ES384 public key")),
            };
            let signature: Signature = match Signature::try_from(signature.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid signature")),
            };
            v = pub_key.verify(&content, &signature).is_ok();
        }
        ES512 => {
            let crv = crv.ok_or(JsValue::from("Invalid curve"))?;
            if crv != keys::P_521 {
                return Err(JsValue::from("Invalid curve"));
            }
            return Err(JsValue::from("ES512 not implemented"));
        }
        PS256 | PS384 | PS512 => {
            use rsa::pkcs8::DecodePublicKey;
            use rsa::pss::{Signature, VerifyingKey};
            use rsa::signature::Verifier;
            use rsa::RsaPublicKey;
            let pub_key = match RsaPublicKey::from_public_key_der(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid RSA public key")),
            };
            if alg == PS256 {
                let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(pub_key);
                let signature: Signature = match Signature::try_from(signature.as_slice()) {
                    Ok(v) => v,
                    Err(_) => return Err(JsValue::from("Invalid signature")),
                };
                v = verifying_key.verify(&content, &signature).is_ok();
            } else if alg == PS384 {
                let verifying_key: VerifyingKey<Sha384> = VerifyingKey::new(pub_key);
                let signature: Signature = match Signature::try_from(signature.as_slice()) {
                    Ok(v) => v,
                    Err(_) => return Err(JsValue::from("Invalid signature")),
                };
                v = verifying_key.verify(&content, &signature).is_ok();
            } else {
                let verifying_key: VerifyingKey<Sha512> = VerifyingKey::new(pub_key);
                let signature: Signature = match Signature::try_from(signature.as_slice()) {
                    Ok(v) => v,
                    Err(_) => return Err(JsValue::from("Invalid signature")),
                };
                v = verifying_key.verify(&content, &signature).is_ok();
            }
        }
        _ => {
            return Err(JsValue::from("Invalid algorithm"));
        }
    }
    Ok(v)
}

fn verify_mac_key(alg: i32, l: usize) -> Result<(), JsValue> {
    let size = match alg {
        AES_MAC_128_64 => 16,
        AES_MAC_256_64 => 32,
        AES_MAC_128_128 => 16,
        AES_MAC_256_128 => 32,
        _ => 0,
    };

    if size != 0 && l != size {
        Err(JsValue::from("Invalid MAC key"))
    } else {
        Ok(())
    }
}
pub(crate) fn mac(alg: i32, key: &Vec<u8>, content: &Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let mut message_digest;
    let size;
    verify_mac_key(alg, key.len())?;
    match alg {
        HMAC_256_64 => {
            let mut mac = match HmacSha256::new_from_slice(key.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid HMAC_256_64 key")),
            };
            mac.update(&content);
            message_digest = mac.finalize().into_bytes().to_vec();
            size = 8;
        }
        HMAC_256_256 => {
            let mut mac = match HmacSha256::new_from_slice(key.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid HMAC_256_256 key")),
            };
            mac.update(&content);
            message_digest = mac.finalize().into_bytes().to_vec();
            size = 32;
        }
        HMAC_384_384 => {
            let mut mac = match HmacSha384::new_from_slice(key.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid HMAC_384_384 key")),
            };
            mac.update(&content);
            message_digest = mac.finalize().into_bytes().to_vec();
            size = 48;
        }
        HMAC_512_512 => {
            let mut mac = match HmacSha512::new_from_slice(key.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid HMAC_512_512 key")),
            };
            mac.update(&content);
            message_digest = mac.finalize().into_bytes().to_vec();
            size = 64;
        }
        AES_MAC_128_64 => {
            let mut mac = match Daa128::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_MAC_128_64 key")),
            };
            mac.update(&content);
            size = 8;
            message_digest = mac.finalize().into_bytes().to_vec();
        }
        AES_MAC_256_64 => {
            let mut mac = match Daa256::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_MAC_256_64 key")),
            };
            mac.update(&content);
            size = 8;
            message_digest = mac.finalize().into_bytes().to_vec();
        }
        AES_MAC_128_128 => {
            let mut mac = match Daa128::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_MAC_128_128 key")),
            };
            mac.update(&content);
            size = 16;
            message_digest = mac.finalize().into_bytes().to_vec();
        }
        AES_MAC_256_128 => {
            let mut mac = match Daa256::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_MAC_256_128 key")),
            };
            mac.update(&content);
            size = 16;
            message_digest = mac.finalize().into_bytes().to_vec();
        }
        _ => {
            return Err(JsValue::from("Invalid algorithm"));
        }
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
    verify_mac_key(alg, key.len())?;
    match alg {
        HMAC_256_64 => {
            let mut mac = match HmacSha256::new_from_slice(key.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid HMAC_256_64 key")),
            };
            mac.update(&content);
            message_digest = mac.finalize().into_bytes().to_vec();
            size = 8;
        }
        HMAC_256_256 => {
            let mut mac = match HmacSha256::new_from_slice(key.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid HMAC_256_256 key")),
            };

            mac.update(&content);
            message_digest = mac.finalize().into_bytes().to_vec();
            size = 32;
        }
        HMAC_384_384 => {
            let mut mac = match HmacSha384::new_from_slice(key.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid HMAC_384_384 key")),
            };
            mac.update(&content);
            message_digest = mac.finalize().into_bytes().to_vec();
            size = 48;
        }
        HMAC_512_512 => {
            let mut mac = match HmacSha512::new_from_slice(key.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid HMAC_512_512 key")),
            };
            mac.update(&content);
            message_digest = mac.finalize().into_bytes().to_vec();
            size = 64;
        }
        AES_MAC_128_64 => {
            let mut mac = match Daa128::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_MAC_128_64 key")),
            };
            mac.update(&content);
            size = 8;
            message_digest = mac.finalize().into_bytes().to_vec();
        }
        AES_MAC_256_64 => {
            let mut mac = match Daa256::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_MAC_256_64 key")),
            };
            mac.update(&content);
            size = 8;
            message_digest = mac.finalize().into_bytes().to_vec();
        }
        AES_MAC_128_128 => {
            let mut mac = match Daa128::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_MAC_128_128 key")),
            };
            mac.update(&content);
            size = 16;
            message_digest = mac.finalize().into_bytes().to_vec();
        }
        AES_MAC_256_128 => {
            let mut mac = match Daa256::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_MAC_256_128 key")),
            };
            mac.update(&content);
            size = 16;
            message_digest = mac.finalize().into_bytes().to_vec();
        }
        _ => {
            return Err(JsValue::from("Invalid algorithm"));
        }
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
    match alg {
        A128GCM => {
            use aes_gcm::{
                aead::{AeadInPlace, KeyInit},
                Aes128Gcm, Nonce,
            };
            let cipher = match Aes128Gcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid A128GCM key")),
            };
            let nonce = Nonce::from_slice(iv);
            match cipher.encrypt_in_place(&nonce, aead, &mut c) {
                Ok(_) => (),
                Err(_) => return Err(JsValue::from("Error during encryption")),
            }
        }
        A192GCM => {
            use aes_gcm::{
                aead::{
                    generic_array::{typenum, GenericArray},
                    AeadInPlace, KeyInit,
                },
                AesGcm, Nonce,
            };

            if key.len() != 24 {
                return Err(JsValue::from("Invalid A192GCM key"));
            }
            let cipher: AesGcm<Aes192, typenum::U12> = AesGcm::new(GenericArray::from_slice(&key));
            let nonce = Nonce::from_slice(iv);
            match cipher.encrypt_in_place(&nonce, aead, &mut c) {
                Ok(_) => (),
                Err(_) => return Err(JsValue::from("Error during encryption")),
            }
        }
        A256GCM => {
            use aes_gcm::{
                aead::{AeadInPlace, KeyInit},
                Aes256Gcm, Nonce,
            };

            let cipher = match Aes256Gcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid A256GCM key")),
            };
            let nonce = Nonce::from_slice(iv);
            match cipher.encrypt_in_place(&nonce, aead, &mut c) {
                Ok(_) => (),
                Err(_) => return Err(JsValue::from("Error during encryption")),
            }
        }
        CHACHA20 => {
            use chacha20poly1305::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                ChaCha20Poly1305,
            };
            let cipher = match ChaCha20Poly1305::new_from_slice(key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid CHACHA20 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.encrypt_in_place(&nonce, aead, &mut c) {
                Ok(_) => (),
                Err(_) => return Err(JsValue::from("Error during encryption")),
            }
        }
        AES_CCM_16_64_128 => {
            use ccm::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                consts::{U13, U8},
                Ccm,
            };
            type AesCcm = Ccm<Aes128, U8, U13>;
            let cipher = match AesCcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_CCM_16_64_128 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.encrypt_in_place(&nonce, aead, &mut c) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Error during encryption")),
            };
        }
        AES_CCM_16_64_256 => {
            use ccm::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                consts::{U13, U8},
                Ccm,
            };
            type AesCcm = Ccm<Aes256, U8, U13>;
            let cipher = match AesCcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_CCM_16_64_256 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.encrypt_in_place(&nonce, aead, &mut c) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Error during encryption")),
            };
        }
        AES_CCM_64_64_128 => {
            use ccm::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                consts::{U7, U8},
                Ccm,
            };
            type AesCcm = Ccm<Aes128, U8, U7>;
            let cipher = match AesCcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_CCM_64_64_128 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.encrypt_in_place(&nonce, aead, &mut c) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Error during encryption")),
            };
        }
        AES_CCM_64_64_256 => {
            use ccm::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                consts::{U7, U8},
                Ccm,
            };
            type AesCcm = Ccm<Aes256, U8, U7>;
            let cipher = match AesCcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_CCM_64_64_256 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.encrypt_in_place(&nonce, aead, &mut c) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Error during encryption")),
            };
        }
        AES_CCM_16_128_128 => {
            use ccm::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                consts::{U13, U16},
                Ccm,
            };
            type AesCcm = Ccm<Aes128, U16, U13>;
            let cipher = match AesCcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_CCM_16_128_128 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.encrypt_in_place(&nonce, aead, &mut c) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Error during encryption")),
            };
        }
        AES_CCM_16_128_256 => {
            use ccm::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                consts::{U13, U16},
                Ccm,
            };
            type AesCcm = Ccm<Aes256, U16, U13>;
            let cipher = match AesCcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_CCM_16_128_256 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.encrypt_in_place(&nonce, aead, &mut c) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Error during encryption")),
            };
        }
        AES_CCM_64_128_128 => {
            use ccm::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                consts::{U16, U7},
                Ccm,
            };
            type AesCcm = Ccm<Aes128, U16, U7>;
            let cipher = match AesCcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_CCM_64_128_128 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.encrypt_in_place(&nonce, aead, &mut c) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Error during encryption")),
            };
        }
        AES_CCM_64_128_256 => {
            use ccm::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                consts::{U16, U7},
                Ccm,
            };
            type AesCcm = Ccm<Aes256, U16, U7>;
            let cipher = match AesCcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_CCM_64_128_256 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.encrypt_in_place(&nonce, aead, &mut c) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Error during encryption")),
            };
        }
        _ => {
            return Err(JsValue::from("Invalid algorithm"));
        }
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
    match alg {
        A128GCM => {
            use aes_gcm::{
                aead::{AeadInPlace, KeyInit},
                Aes128Gcm, Nonce,
            };
            let cipher = match Aes128Gcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid A128GCM key")),
            };
            let nonce = Nonce::from_slice(iv);
            match cipher.decrypt_in_place(&nonce, aead, &mut c) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Error during decrypt")),
            };
        }
        A192GCM => {
            use aes_gcm::{
                aead::{
                    generic_array::{typenum, GenericArray},
                    AeadInPlace, KeyInit,
                },
                AesGcm, Nonce,
            };

            if key.len() != 24 {
                return Err(JsValue::from("Invalid A192GCM key"));
            }
            let cipher: AesGcm<Aes192, typenum::U12> = AesGcm::new(GenericArray::from_slice(&key));
            let nonce = Nonce::from_slice(iv);
            match cipher.decrypt_in_place(&nonce, aead, &mut c) {
                Ok(_) => (),
                Err(_) => return Err(JsValue::from("Error during decrypt")),
            };
        }
        A256GCM => {
            use aes_gcm::{
                aead::{AeadInPlace, KeyInit},
                Aes256Gcm, Nonce,
            };

            let cipher = match Aes256Gcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid A256GCM key")),
            };
            let nonce = Nonce::from_slice(iv);
            match cipher.decrypt_in_place(&nonce, aead, &mut c) {
                Ok(_) => (),
                Err(_) => return Err(JsValue::from("Error during decrypt")),
            };
        }
        CHACHA20 => {
            use chacha20poly1305::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                ChaCha20Poly1305,
            };
            let cipher = match ChaCha20Poly1305::new_from_slice(key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid CHACHA20 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.decrypt_in_place(&nonce, aead, &mut c) {
                Ok(_) => (),
                Err(_) => return Err(JsValue::from("Error during decrypt")),
            };
        }
        AES_CCM_16_64_128 => {
            use ccm::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                consts::{U13, U8},
                Ccm,
            };
            type AesCcm = Ccm<Aes128, U8, U13>;
            let cipher = match AesCcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_CCM_16_64_128 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.decrypt_in_place(&nonce, aead, &mut c) {
                Ok(_) => (),
                Err(_) => return Err(JsValue::from("Error during decrypt")),
            };
        }
        AES_CCM_16_64_256 => {
            use ccm::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                consts::{U13, U8},
                Ccm,
            };
            type AesCcm = Ccm<Aes256, U8, U13>;
            let cipher = match AesCcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_CCM_16_64_256 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.decrypt_in_place(&nonce, aead, &mut c) {
                Ok(_) => (),
                Err(_) => return Err(JsValue::from("Error during decrypt")),
            };
        }
        AES_CCM_64_64_128 => {
            use ccm::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                consts::{U7, U8},
                Ccm,
            };
            type AesCcm = Ccm<Aes128, U8, U7>;
            let cipher = match AesCcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_CCM_64_64_128 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.decrypt_in_place(&nonce, aead, &mut c) {
                Ok(_) => (),
                Err(_) => return Err(JsValue::from("Error during decrypt")),
            };
        }
        AES_CCM_64_64_256 => {
            use ccm::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                consts::{U7, U8},
                Ccm,
            };
            type AesCcm = Ccm<Aes256, U8, U7>;
            let cipher = match AesCcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_CCM_64_64_256 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.decrypt_in_place(&nonce, aead, &mut c) {
                Ok(_) => (),
                Err(_) => return Err(JsValue::from("Error during decrypt")),
            };
        }
        AES_CCM_16_128_128 => {
            use ccm::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                consts::{U13, U16},
                Ccm,
            };
            type AesCcm = Ccm<Aes128, U16, U13>;
            let cipher = match AesCcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_CCM_16_128_128 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.decrypt_in_place(&nonce, aead, &mut c) {
                Ok(_) => (),
                Err(_) => return Err(JsValue::from("Error during decrypt")),
            };
        }
        AES_CCM_16_128_256 => {
            use ccm::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                consts::{U13, U16},
                Ccm,
            };
            type AesCcm = Ccm<Aes256, U16, U13>;
            let cipher = match AesCcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_CCM_16_128_256 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.decrypt_in_place(&nonce, aead, &mut c) {
                Ok(_) => (),
                Err(_) => return Err(JsValue::from("Error during decrypt")),
            };
        }
        AES_CCM_64_128_128 => {
            use ccm::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                consts::{U16, U7},
                Ccm,
            };
            type AesCcm = Ccm<Aes128, U16, U7>;
            let cipher = match AesCcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_CCM_64_128_128 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.decrypt_in_place(&nonce, aead, &mut c) {
                Ok(_) => (),
                Err(_) => return Err(JsValue::from("Error during decrypt")),
            };
        }
        AES_CCM_64_128_256 => {
            use ccm::{
                aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
                consts::{U16, U7},
                Ccm,
            };
            type AesCcm = Ccm<Aes256, U16, U7>;
            let cipher = match AesCcm::new_from_slice(&key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid AES_CCM_64_128_256 key")),
            };
            let nonce = GenericArray::from_slice(iv);
            match cipher.decrypt_in_place(&nonce, aead, &mut c) {
                Ok(_) => (),
                Err(_) => return Err(JsValue::from("Error during decrypt")),
            };
        }
        _ => {
            return Err(JsValue::from("Invalid algorithm"));
        }
    }

    Ok(c)
}

pub(crate) fn aes_key_wrap(key: &Vec<u8>, alg: i32, cek: &Vec<u8>) -> Result<Vec<u8>, JsValue> {
    match alg {
        A128KW => {
            let kek: KekAes128 = match Kek::try_from(key.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid A128KW key")),
            };
            match kek.wrap_vec(cek) {
                Ok(v) => Ok(v),
                Err(_) => return Err(JsValue::from("Error during Key Wrap")),
            }
        }
        A192KW => {
            let kek: KekAes192 = match Kek::try_from(key.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid A192KW key")),
            };
            match kek.wrap_vec(cek) {
                Ok(v) => Ok(v),
                Err(_) => return Err(JsValue::from("Error during Key Wrap")),
            }
        }
        A256KW => {
            let kek: KekAes256 = match Kek::try_from(key.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid A256KW key")),
            };
            match kek.wrap_vec(cek) {
                Ok(v) => Ok(v),
                Err(_) => return Err(JsValue::from("Error during Key Wrap")),
            }
        }
        _ => {
            return Err(JsValue::from("Invalid algorithm"));
        }
    }
}

pub(crate) fn aes_key_unwrap(key: &Vec<u8>, alg: i32, cek: &Vec<u8>) -> Result<Vec<u8>, JsValue> {
    match alg {
        A128KW => {
            let kek: KekAes128 = match Kek::try_from(key.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid A128KW key")),
            };
            match kek.unwrap_vec(cek) {
                Ok(v) => Ok(v),
                Err(_) => return Err(JsValue::from("Error during Key Unwrap")),
            }
        }
        A192KW => {
            let kek: KekAes192 = match Kek::try_from(key.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid A192KW key")),
            };
            match kek.unwrap_vec(cek) {
                Ok(v) => Ok(v),
                Err(_) => return Err(JsValue::from("Error during Key Unwrap")),
            }
        }
        A256KW => {
            let kek: KekAes256 = match Kek::try_from(key.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid A256KW key")),
            };
            match kek.unwrap_vec(cek) {
                Ok(v) => Ok(v),
                Err(_) => return Err(JsValue::from("Error during Key Unwrap")),
            }
        }
        _ => {
            return Err(JsValue::from("Invalid algorithm"));
        }
    }
}
pub(crate) fn rsa_oaep_enc(key: &Vec<u8>, cek: &Vec<u8>, alg: &i32) -> Result<Vec<u8>, JsValue> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::{Oaep, RsaPublicKey};
    let rsa_key = match RsaPublicKey::from_public_key_der(key) {
        Ok(v) => v,
        Err(_) => return Err(JsValue::from("Invalid RSA OAEP key")),
    };
    match *alg {
        RSA_OAEP_1 => {
            let padding = Oaep::new::<Sha1>();
            let mut rng = rand::thread_rng();

            match rsa_key.encrypt(&mut rng, padding, &cek) {
                Ok(v) => Ok(v.to_vec()),
                Err(_) => Err(JsValue::from("Error during Encryption")),
            }
        }
        RSA_OAEP_256 => {
            let padding = Oaep::new::<Sha256>();
            let mut rng = rand::thread_rng();

            match rsa_key.encrypt(&mut rng, padding, &cek) {
                Ok(v) => Ok(v.to_vec()),
                Err(_) => Err(JsValue::from("Error during Encryption")),
            }
        }
        RSA_OAEP_512 => {
            let padding = Oaep::new::<Sha512>();
            let mut rng = rand::thread_rng();

            match rsa_key.encrypt(&mut rng, padding, &cek) {
                Ok(v) => Ok(v.to_vec()),
                Err(_) => Err(JsValue::from("Error during Encryption")),
            }
        }
        _ => {
            return Err(JsValue::from("Invalid algorithm"));
        }
    }
}

pub(crate) fn rsa_oaep_dec(
    key: &Vec<u8>,
    size: usize,
    cek: &Vec<u8>,
    alg: &i32,
) -> Result<Vec<u8>, JsValue> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::{Oaep, RsaPrivateKey};
    let rsa_key = match RsaPrivateKey::from_pkcs1_der(key) {
        Ok(v) => v,
        Err(_) => return Err(JsValue::from("Invalid RSA OAEP key")),
    };
    match *alg {
        RSA_OAEP_1 => {
            let padding = Oaep::new::<Sha1>();
            match rsa_key.decrypt(padding, &cek) {
                Ok(v) => Ok(v[..size].to_vec()),
                Err(_) => Err(JsValue::from("Error during Decryption")),
            }
        }
        RSA_OAEP_256 => {
            let padding = Oaep::new::<Sha256>();
            match rsa_key.decrypt(padding, &cek) {
                Ok(v) => Ok(v[..size].to_vec()),
                Err(_) => Err(JsValue::from("Error during Decryption")),
            }
        }
        RSA_OAEP_512 => {
            let padding = Oaep::new::<Sha512>();
            match rsa_key.decrypt(padding, &cek) {
                Ok(v) => Ok(v[..size].to_vec()),
                Err(_) => Err(JsValue::from("Error during Decryption")),
            }
        }
        _ => {
            return Err(JsValue::from("Invalid algorithm"));
        }
    }
}

pub(crate) fn ecdh_derive_key(
    crv_rec: i32,
    crv_send: i32,
    receiver_key: &Vec<u8>,
    sender_key: &Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    if crv_rec != crv_send {
        return Err("ECDH curves don't match".into());
    } else if [keys::X448, keys::X25519].contains(&crv_send) {
        return Err("X448 and X25519 not implemented".into());
    } else if crv_send == keys::P_256 {
        use p256::{ecdh, PublicKey, SecretKey};
        return Ok(ecdh::diffie_hellman(
            match SecretKey::from_be_bytes(&sender_key) {
                Ok(v) => v.to_nonzero_scalar(),
                Err(_) => return Err(JsValue::from("Invalid ECDH private key")),
            },
            match PublicKey::from_sec1_bytes(&receiver_key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid ECDH public key")),
            }
            .as_affine(),
        )
        .raw_secret_bytes()
        .to_vec());
    } else if crv_send == keys::P_384 {
        use p384::{ecdh, PublicKey, SecretKey};
        return Ok(ecdh::diffie_hellman(
            match SecretKey::from_be_bytes(&sender_key) {
                Ok(v) => v.to_nonzero_scalar(),
                Err(_) => return Err(JsValue::from("Invalid ECDH private key")),
            },
            match PublicKey::from_sec1_bytes(&receiver_key) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid ECDH public key")),
            }
            .as_affine(),
        )
        .raw_secret_bytes()
        .to_vec());
    } else if crv_send == keys::P_521 {
        return Err(JsValue::from("P_521 not implemented"));
    } else {
        return Err(JsValue::from("Invalid curve"));
    }
}

pub(crate) fn hkdf(
    length: usize,
    ikm: &Vec<u8>,
    salt_input: Option<&Vec<u8>>,
    info_input: &mut Vec<u8>,
    alg: i32,
) -> Result<Vec<u8>, JsValue> {
    if HKDF_ALGS.contains(&alg) {
        if [DIRECT_HKDF_AES_128, DIRECT_HKDF_AES_256].contains(&alg) {
            let mut t = Vec::new();
            let mut okm = Vec::new();
            let mut i = 0;
            while okm.len() < length {
                i += 1;
                let mut info_tmp = info_input.clone();
                t.append(&mut info_tmp);
                t.append(&mut vec![i]);
                let mut padded: Vec<u8> = t.clone();
                if padded.len() % 16 != 0 {
                    padded.append(&mut vec![0; 16 - (padded.len() % 16)]);
                }

                let s;

                if alg == DIRECT_HKDF_AES_128 {
                    let mut mac = match Daa128::new_from_slice(&ikm) {
                        Ok(v) => v,
                        Err(_) => return Err(JsValue::from("Invalid HKDF (MAC) key")),
                    };
                    mac.update(&padded);
                    s = mac.finalize().into_bytes().to_vec();
                } else {
                    let mut mac = match Daa256::new_from_slice(&ikm) {
                        Ok(v) => v,
                        Err(_) => return Err(JsValue::from("Invalid HKDF (MAC) key")),
                    };
                    mac.update(&padded);
                    s = mac.finalize().into_bytes().to_vec();
                }
                t = s.clone();
                t.truncate(16);
                let mut temp = t.clone();
                okm.append(&mut temp);
            }
            return Ok(okm[..length].to_vec());
        }

        let salt = match salt_input {
            Some(v) => Some(v.as_slice()),
            None => None,
        };
        let mut okm = [0u8; 64];
        if [ECDH_ES_HKDF_512, ECDH_SS_HKDF_512, DIRECT_HKDF_SHA_512].contains(&alg) {
            let hk = Hkdf::<Sha512>::new(salt, &ikm);
            match hk.expand(&info_input, &mut okm) {
                Ok(_) => (),
                Err(_) => return Err(JsValue::from("Error during HKDF expand")),
            };
            return Ok(okm[..length as usize].to_vec());
        }
        let hk = Hkdf::<Sha256>::new(salt, &ikm);
        match hk.expand(&info_input, &mut okm) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during HKDF expand")),
        };
        return Ok(okm[..length as usize].to_vec());
    } else {
        return Err(JsValue::from("Invalid algorithm"));
    }
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
        Err(JsValue::from("Invalid algorithm"))
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
        Err(JsValue::from("Invalid algorithm"))
    }
}

pub(crate) fn get_iv_size(alg: &i32) -> Result<usize, JsValue> {
    match *alg {
        A128GCM | A192GCM | A256GCM | CHACHA20 => Ok(12),
        AES_CCM_16_64_128 | AES_CCM_16_64_256 | AES_CCM_16_128_256 => Ok(13),
        AES_CCM_64_64_128 | AES_CCM_64_64_256 | AES_CCM_64_128_256 => Ok(7),
        _ => Err(JsValue::from("Invalid algorithm")),
    }
}

pub(crate) fn gen_iv(
    partial_iv: &Vec<u8>,
    base_iv: &Vec<u8>,
    alg: &i32,
) -> Result<Vec<u8>, JsValue> {
    let size = get_iv_size(alg)?;
    let mut pv = partial_iv.clone();
    let mut padded = vec![0; size - pv.len()];
    padded.append(&mut pv);
    let mut iv = Vec::new();
    for i in 0..padded.len() {
        if i < base_iv.len() {
            iv.push(padded[i] ^ base_iv[i]);
        } else {
            iv.push(padded[i]);
        }
    }
    Ok(iv)
}

#[cfg(test)]
mod unit_tests {
    use crate::algs;
    use crate::keys;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn digital_signature_invalid_alg() {
        assert_eq!(
            algs::sign(0, None, &vec![], &vec![]),
            Err("Invalid algorithm".into())
        );
        assert_eq!(
            algs::verify(0, None, &vec![], &vec![], &vec![]),
            Err("Invalid algorithm".into())
        );
        assert_eq!(
            algs::sign(algs::A128GCM, None, &vec![], &vec![]),
            Err("Invalid algorithm".into())
        );
        assert_eq!(
            algs::verify(algs::A128GCM, None, &vec![], &vec![], &vec![]),
            Err("Invalid algorithm".into())
        );
    }
    #[wasm_bindgen_test]
    fn digital_signature_invalid_crv() {
        assert_eq!(
            algs::sign(algs::ES256, None, &vec![], &vec![]),
            Err("Missing curve".into())
        );
        assert_eq!(
            algs::verify(algs::ES256, None, &vec![], &vec![], &vec![]),
            Err("Missing curve".into())
        );
        assert_eq!(
            algs::sign(algs::ES256, Some(0), &vec![], &vec![]),
            Err("Invalid curve".into())
        );
        assert_eq!(
            algs::verify(algs::ES256, Some(0), &vec![], &vec![], &vec![]),
            Err("Invalid curve".into())
        );

        let ec_algs: [i32; 5] = [
            algs::ES256,
            algs::ES384,
            algs::ES512,
            algs::EDDSA,
            algs::ES256K,
        ];
        let valid_pairs = [
            (algs::ES256, keys::P_256),
            (algs::ES384, keys::P_384),
            (algs::ES512, keys::P_521),
            (algs::EDDSA, keys::ED25519),
            (algs::EDDSA, keys::ED448),
            (algs::ES256K, keys::SECP256K1),
        ];
        for alg in ec_algs {
            for curve in keys::CURVES_ALL {
                if valid_pairs.contains(&(alg, curve)) {
                    assert_ne!(
                        algs::sign(alg, Some(curve), &vec![], &vec![]),
                        Err("Invalid curve".into())
                    );
                    assert_ne!(
                        algs::verify(alg, Some(curve), &vec![], &vec![], &vec![]),
                        Err("Invalid curve".into())
                    );
                } else {
                    assert_eq!(
                        algs::sign(alg, Some(curve), &vec![], &vec![]),
                        Err("Invalid curve".into())
                    );
                    assert_eq!(
                        algs::verify(alg, Some(curve), &vec![], &vec![], &vec![]),
                        Err("Invalid curve".into())
                    );
                }
            }
        }
    }

    #[wasm_bindgen_test]
    fn digital_signature_invalid_key() {
        let valid_pairs = [
            (algs::ES256, Some(keys::P_256)),
            (algs::ES384, Some(keys::P_384)),
            (algs::ES512, Some(keys::P_521)),
            (algs::EDDSA, Some(keys::ED25519)),
            (algs::EDDSA, Some(keys::ED448)),
            (algs::ES256K, Some(keys::SECP256K1)),
            (algs::PS256, None),
            (algs::PS384, None),
            (algs::PS512, None),
        ];

        for pair in valid_pairs {
            let out_sign = algs::sign(pair.0, pair.1, &vec![0], &vec![]);
            let out_verify = algs::verify(pair.0, pair.1, &vec![0], &vec![], &vec![]);
            assert!(out_sign.is_err());
            assert!(out_verify.is_err());
            let err_sign = out_sign.unwrap_err().as_string().unwrap();
            let err_verify = out_verify.unwrap_err().as_string().unwrap();

            if pair.0 == algs::ES512 || pair.1 == Some(keys::ED448) {
                assert!(err_sign.contains("not implemented"));
                assert!(err_verify.contains("not implemented"));
            } else {
                assert!(err_sign.contains("Invalid") && err_sign.contains("private key"));
                assert!(err_verify.contains("Invalid") && err_verify.contains("public key"));
            }
        }
    }

    #[wasm_bindgen_test]
    fn mac_invalid_alg() {
        assert_eq!(
            algs::mac(0, &vec![], &vec![]),
            Err("Invalid algorithm".into())
        );
        assert_eq!(
            algs::mac_verify(0, &vec![], &vec![], &vec![]),
            Err("Invalid algorithm".into())
        );
        assert_eq!(
            algs::mac(algs::ES256, &vec![], &vec![]),
            Err("Invalid algorithm".into())
        );
        assert_eq!(
            algs::mac_verify(algs::ES256, &vec![], &vec![], &vec![]),
            Err("Invalid algorithm".into())
        );
    }
    #[wasm_bindgen_test]
    fn mac_invalid_key() {
        for alg in [
            algs::AES_MAC_128_64,
            algs::AES_MAC_256_64,
            algs::AES_MAC_128_128,
            algs::AES_MAC_256_128,
        ] {
            let out_mac = algs::mac(alg, &vec![0], &vec![]);
            let out_verify = algs::mac_verify(alg, &vec![0], &vec![], &vec![]);
            assert!(out_mac.is_err());
            assert!(out_verify.is_err());

            let err_mac = out_mac.unwrap_err().as_string().unwrap();
            let err_verify = out_verify.unwrap_err().as_string().unwrap();

            assert!(err_mac.contains("Invalid") && err_mac.contains("key"));
            assert!(err_verify.contains("Invalid") && err_verify.contains("key"));
            assert_eq!(err_mac, err_verify);
        }
    }

    #[wasm_bindgen_test]
    fn encryption_invalid_alg() {
        assert_eq!(
            algs::encrypt(0, &vec![], &vec![], &vec![], &vec![]),
            Err("Invalid algorithm".into())
        );
        assert_eq!(
            algs::decrypt(0, &vec![], &vec![], &vec![], &vec![]),
            Err("Invalid algorithm".into())
        );
        assert_eq!(
            algs::encrypt(algs::ES256, &vec![], &vec![], &vec![], &vec![]),
            Err("Invalid algorithm".into())
        );
        assert_eq!(
            algs::decrypt(algs::ES256, &vec![], &vec![], &vec![], &vec![]),
            Err("Invalid algorithm".into())
        );
    }
    #[wasm_bindgen_test]
    fn encryption_invalid_key() {
        for alg in algs::ENCRYPT_ALGS {
            let out_enc = algs::encrypt(alg, &vec![0], &vec![], &vec![], &vec![]);
            let out_dec = algs::decrypt(alg, &vec![0], &vec![], &vec![], &vec![]);
            assert!(out_enc.is_err());
            assert!(out_dec.is_err());

            let err_enc = out_enc.unwrap_err().as_string().unwrap();
            let err_dec = out_dec.unwrap_err().as_string().unwrap();

            assert!(err_enc.contains("Invalid") && err_enc.contains("key"));
            assert!(err_dec.contains("Invalid") && err_dec.contains("key"));
        }
    }

    #[wasm_bindgen_test]
    fn rsa_oaep_invalid_alg() {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::pkcs8::EncodePublicKey;
        use rsa::{RsaPrivateKey, RsaPublicKey};

        let mut rng = rand::thread_rng();
        let rsa_priv_key = RsaPrivateKey::new(&mut rng, 256).unwrap();
        let rsa_pub_key = RsaPublicKey::from(&rsa_priv_key);

        let priv_key = rsa_priv_key.to_pkcs1_der().unwrap().to_bytes();
        let pub_key = rsa_pub_key.to_public_key_der().unwrap().to_vec();

        assert_eq!(
            algs::rsa_oaep_enc(&pub_key, &vec![], &0),
            Err("Invalid algorithm".into())
        );
        assert_eq!(
            algs::rsa_oaep_dec(&priv_key, 16, &vec![], &0),
            Err("Invalid algorithm".into())
        );
        assert_eq!(
            algs::rsa_oaep_enc(&pub_key, &vec![], &algs::ES256),
            Err("Invalid algorithm".into())
        );
        assert_eq!(
            algs::rsa_oaep_dec(&priv_key, 16, &vec![], &algs::ES256),
            Err("Invalid algorithm".into())
        );
    }

    #[wasm_bindgen_test]
    fn rsa_oaep_invalid_key() {
        for alg in [algs::RSA_OAEP_1, algs::RSA_OAEP_256, algs::RSA_OAEP_512] {
            let out_enc = algs::rsa_oaep_enc(&vec![0], &vec![], &alg);
            let out_dec = algs::rsa_oaep_dec(&vec![0], 16, &vec![], &alg);
            assert!(out_enc.is_err());
            assert!(out_dec.is_err());

            let err_enc = out_enc.unwrap_err().as_string().unwrap();
            let err_dec = out_dec.unwrap_err().as_string().unwrap();

            assert!(err_enc.contains("Invalid") && err_enc.contains("key"));
            assert!(err_dec.contains("Invalid") && err_dec.contains("key"));
            assert_eq!(err_enc, err_dec);
        }
    }

    #[wasm_bindgen_test]
    fn aes_key_wrap_invalid_alg() {
        assert_eq!(
            algs::aes_key_wrap(&vec![], 0, &vec![]),
            Err("Invalid algorithm".into())
        );
        assert_eq!(
            algs::aes_key_unwrap(&vec![], 0, &vec![]),
            Err("Invalid algorithm".into())
        );
        assert_eq!(
            algs::aes_key_wrap(&vec![], algs::ES256, &vec![]),
            Err("Invalid algorithm".into())
        );
        assert_eq!(
            algs::aes_key_unwrap(&vec![], algs::ES256, &vec![]),
            Err("Invalid algorithm".into())
        );
    }

    #[wasm_bindgen_test]
    fn aes_key_wrap_invalid_key() {
        for alg in [algs::A128KW, algs::A192KW, algs::A256KW] {
            let out_wrap = algs::aes_key_wrap(&vec![0], alg, &vec![]);
            let out_unwrap = algs::aes_key_unwrap(&vec![0], alg, &vec![]);
            assert!(out_wrap.is_err());
            assert!(out_unwrap.is_err());

            let err_wrap = out_wrap.unwrap_err().as_string().unwrap();
            let err_unwrap = out_unwrap.unwrap_err().as_string().unwrap();

            assert!(err_wrap.contains("Invalid") && err_wrap.contains("key"));
            assert!(err_unwrap.contains("Invalid") && err_unwrap.contains("key"));
            assert_eq!(err_wrap, err_unwrap);
        }
    }

    #[wasm_bindgen_test]
    fn ecdh_invalid_curves() {
        let not_implemented = [keys::X448, keys::X25519, keys::P_521];
        for curve in not_implemented {
            assert!(algs::ecdh_derive_key(curve, curve, &vec![], &vec![])
                .unwrap_err()
                .as_string()
                .unwrap()
                .contains("not implemented"));
        }

        assert_eq!(
            algs::ecdh_derive_key(keys::P_256, keys::P_384, &vec![], &vec![]),
            Err("ECDH curves don't match".into())
        );
        assert_eq!(
            algs::ecdh_derive_key(0, 0, &vec![], &vec![]),
            Err("Invalid curve".into())
        );
    }

    #[wasm_bindgen_test]
    fn ecdh_invalid_key() {
        for curve in [keys::P_256, keys::P_384] {
            let out = algs::ecdh_derive_key(curve, curve, &vec![0], &vec![0]);
            assert!(out.is_err());

            let err = out.unwrap_err().as_string().unwrap();
            assert!(err.contains("Invalid") && err.contains("key"));
        }
    }

    #[wasm_bindgen_test]
    fn hkdf_invalid_alg() {
        assert_eq!(
            algs::hkdf(0, &vec![], None, &mut vec![], 0),
            Err("Invalid algorithm".into())
        );
        assert_eq!(
            algs::hkdf(0, &vec![], None, &mut vec![], algs::ES256),
            Err("Invalid algorithm".into())
        );
    }
}

#[cfg(test)]
mod vector_tests {
    use crate::algs;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn deterministic_sign() {
        let params_csv = include_str!("../test_params/deterministic_sign.csv");
        let mut params: Vec<Vec<&str>> = Vec::new();
        for line in params_csv.lines().skip(1) {
            params.push(line.split(',').map(|s| s.trim()).collect());
        }

        assert!(!params.is_empty());
        for i in 0..params.len() {
            let alg = params[i][0].parse::<i32>().unwrap();
            let crv = params[i][1].parse::<i32>().unwrap();
            let s_key = hex::decode(params[i][2]).unwrap();
            let p_key = hex::decode(params[i][3]).unwrap();
            let wrong_p_key = hex::decode(params[i][4]).unwrap();
            let msg = hex::decode(params[i][5]).unwrap();
            let sig = hex::decode(params[i][6]).unwrap();

            assert_eq!(algs::sign(alg, Some(crv), &s_key, &msg).unwrap(), sig);

            // Remove message byte
            let mut truncated_msg = msg.clone();
            truncated_msg.pop();
            assert_ne!(
                algs::sign(alg, Some(crv), &s_key, &truncated_msg).unwrap(),
                sig
            );

            // Flip message byte
            let mut malformed_msg = msg.clone();
            malformed_msg[0] ^= 0xFF;
            assert_ne!(
                algs::sign(alg, Some(crv), &s_key, &malformed_msg).unwrap(),
                sig
            );

            assert!(algs::verify(alg, Some(crv), &p_key, &msg, &sig).unwrap());

            // Remove signature byte
            let mut truncated_sig = sig.clone();
            truncated_sig.pop();
            assert!(algs::verify(alg, Some(crv), &p_key, &msg, &truncated_sig).is_err());

            // Flip signature byte
            let mut malformed_sig = sig.clone();
            malformed_sig[0] ^= 0xFF;
            assert!(!algs::verify(alg, Some(crv), &p_key, &msg, &malformed_sig).unwrap());

            // Wrong public keys
            assert!(!algs::verify(alg, Some(crv), &wrong_p_key, &msg, &sig).unwrap());
        }
    }

    #[wasm_bindgen_test]
    fn probabilistic_verify() {
        use rsa::pkcs8::EncodePublicKey;
        use rsa::BigUint;
        use rsa::RsaPublicKey;

        let params_csv = include_str!("../test_params/probabilistic_verify.csv");
        let mut params: Vec<Vec<&str>> = Vec::new();
        for line in params_csv.lines().skip(1) {
            params.push(line.split(',').map(|s| s.trim()).collect());
        }

        assert!(!params.is_empty());

        for i in 0..params.len() {
            let alg = params[i][0].parse::<i32>().unwrap();
            let n = hex::decode(params[i][1]).unwrap();
            let e = hex::decode(params[i][2]).unwrap();
            let wrong_n = hex::decode(params[i][3]).unwrap();
            let wrong_e = hex::decode(params[i][4]).unwrap();
            let msg = hex::decode(params[i][5]).unwrap();
            let sig = hex::decode(params[i][6]).unwrap();

            let rsa_pub =
                RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e)).unwrap();
            let p_key = rsa_pub.to_public_key_der().unwrap().to_vec();
            assert!(algs::verify(alg, None, &p_key, &msg, &sig).unwrap());

            // Remove signature byte
            let mut truncated_sig = sig.clone();
            truncated_sig.pop();
            assert!(!algs::verify(alg, None, &p_key, &msg, &truncated_sig).unwrap());

            // Flip signature byte
            let mut malformed_sig = sig.clone();
            malformed_sig[0] ^= 0xFF;
            assert!(!algs::verify(alg, None, &p_key, &msg, &malformed_sig).unwrap());

            // Wrong public keys
            let wrong_rsa_pub = RsaPublicKey::new(
                BigUint::from_bytes_be(&wrong_n),
                BigUint::from_bytes_be(&wrong_e),
            )
            .unwrap();
            let wrong_p_key = wrong_rsa_pub.to_public_key_der().unwrap().to_vec();
            assert!(!algs::verify(alg, None, &wrong_p_key, &msg, &sig).unwrap());
        }
    }
    #[wasm_bindgen_test]
    fn probabilistic_sign() {
        let params_csv = include_str!("../test_params/probabilistic_sign.csv");
        let mut params: Vec<Vec<&str>> = Vec::new();
        for line in params_csv.lines().skip(1) {
            params.push(line.split(',').map(|s| s.trim()).collect());
        }

        assert!(!params.is_empty());

        for alg in [algs::PS256, algs::PS384, algs::PS512] {
            let signature =
                algs::sign(alg, None, &hex::decode(params[0][0]).unwrap(), &vec![]).unwrap();

            assert!(algs::verify(
                alg,
                None,
                &hex::decode(params[0][1]).unwrap(),
                &vec![],
                &signature
            )
            .unwrap());
            assert!(!algs::verify(
                alg,
                None,
                &hex::decode(params[1][1]).unwrap(),
                &vec![],
                &signature
            )
            .unwrap());
        }
    }

    #[wasm_bindgen_test]
    fn mac() {
        let params_csv = include_str!("../test_params/mac.csv");
        let mut params: Vec<Vec<&str>> = Vec::new();
        for line in params_csv.lines().skip(1) {
            params.push(line.split(',').map(|s| s.trim()).collect());
        }
        assert!(!params.is_empty());

        for i in 0..params.len() {
            let alg = params[i][0].parse::<i32>().unwrap();
            let size = params[i][1].parse::<usize>().unwrap();
            let k = hex::decode(params[i][2]).unwrap();
            let msg = hex::decode(params[i][3]).unwrap();
            let mac = hex::decode(params[i][4]).unwrap();

            assert_eq!(algs::mac(alg, &k, &msg).unwrap(), mac[0..size]);

            // Add extra byte to msg
            let mut altered_msg = msg.clone();
            altered_msg.push(0);
            assert_ne!(algs::mac(alg, &k, &altered_msg).unwrap(), mac[0..size]);

            assert!(algs::mac_verify(alg, &k, &msg, &mac[0..size].to_vec()).unwrap());

            // Flip mac byte
            let mut malformed_mac = mac.clone();
            malformed_mac[0] ^= 0xFF;
            assert!(!algs::mac_verify(alg, &k, &msg, &malformed_mac[0..size].to_vec()).unwrap());

            // Wrong key
            let mut wrong_k = k.clone();
            wrong_k[0] ^= 0xFF;
            assert!(
                !algs::mac_verify(alg, &wrong_k, &msg, &malformed_mac[0..size].to_vec()).unwrap()
            );
        }
    }

    #[wasm_bindgen_test]
    fn encrypt() {
        let params_csv = include_str!("../test_params/encrypt.csv");
        let mut params: Vec<Vec<&str>> = Vec::new();
        for line in params_csv.lines().skip(1) {
            params.push(line.split(',').map(|s| s.trim()).collect());
        }
        assert!(!params.is_empty());

        for i in 0..params.len() {
            let alg = params[i][0].parse::<i32>().unwrap();
            let k = hex::decode(params[i][1]).unwrap();
            let nonce = hex::decode(params[i][2]).unwrap();
            let aad = hex::decode(params[i][3]).unwrap();
            let msg = hex::decode(params[i][4]).unwrap();
            let enc = hex::decode(params[i][5]).unwrap();

            assert_eq!(algs::encrypt(alg, &k, &nonce, &msg, &aad).unwrap(), enc);

            // Add extra byte to msg
            let mut altered_msg = msg.clone();
            altered_msg.push(0);
            assert_ne!(
                algs::encrypt(alg, &k, &nonce, &altered_msg, &aad).unwrap(),
                enc
            );

            if !aad.is_empty() {
                // Flip aad byte
                let mut altered_aad = aad.clone();
                altered_aad[0] ^= 0xFF;
                assert_ne!(
                    algs::encrypt(alg, &k, &nonce, &msg, &altered_aad).unwrap(),
                    enc
                );
            }

            assert_eq!(algs::decrypt(alg, &k, &nonce, &enc, &aad).unwrap(), msg);

            // Flip mac byte
            let mut malformed_enc = enc.clone();
            malformed_enc[0] ^= 0xFF;
            assert!(algs::decrypt(alg, &k, &nonce, &malformed_enc, &aad).is_err());

            // Wrong key
            let mut wrong_k = k.clone();
            wrong_k[0] ^= 0xFF;
            assert!(algs::decrypt(alg, &wrong_k, &nonce, &enc, &aad).is_err(),);
        }
    }

    #[wasm_bindgen_test]
    fn ecdh() {
        let params_csv = include_str!("../test_params/ecdh.csv");
        let mut params: Vec<Vec<&str>> = Vec::new();
        for line in params_csv.lines().skip(1) {
            params.push(line.split(',').map(|s| s.trim()).collect());
        }

        assert!(!params.is_empty());

        for i in 0..params.len() {
            let crv = params[i][0].parse::<i32>().unwrap();
            let send_key = hex::decode(params[i][1]).unwrap();
            let rec_key = hex::decode(params[i][2]).unwrap();
            let derived_key = hex::decode(params[i][3]).unwrap();
            let wrong_send_key = hex::decode(params[i][4]).unwrap();
            let wrong_rec_key = hex::decode(params[i][5]).unwrap();

            assert_eq!(
                algs::ecdh_derive_key(crv, crv, &rec_key, &send_key).unwrap(),
                derived_key
            );

            // Wrong receiver key
            assert_ne!(
                algs::ecdh_derive_key(crv, crv, &wrong_rec_key, &send_key).unwrap(),
                derived_key
            );

            // Wrong sender key
            assert_ne!(
                algs::ecdh_derive_key(crv, crv, &rec_key, &wrong_send_key).unwrap(),
                derived_key
            );

            // Wrong keys
            assert_ne!(
                algs::ecdh_derive_key(crv, crv, &wrong_rec_key, &wrong_send_key).unwrap(),
                derived_key
            );
        }
    }
    #[wasm_bindgen_test]
    fn hkdf() {
        let params_csv = include_str!("../test_params/hkdf.csv");
        let mut params: Vec<Vec<&str>> = Vec::new();
        for line in params_csv.lines().skip(1) {
            params.push(line.split(',').map(|s| s.trim()).collect());
        }
        assert!(!params.is_empty());

        for i in 0..params.len() {
            let alg = params[i][0].parse::<i32>().unwrap();
            let l = params[i][1].parse::<usize>().unwrap();
            let ikm = hex::decode(params[i][2]).unwrap();
            let salt = hex::decode(params[i][3]).unwrap();
            let mut info = hex::decode(params[i][4]).unwrap();
            let okm = hex::decode(params[i][5]).unwrap();

            assert_eq!(
                algs::hkdf(l, &ikm, Some(&salt), &mut info, alg).unwrap(),
                okm
            );

            // Add extra byte to info
            let mut altered_info = info.clone();
            altered_info.push(0);
            assert_ne!(
                algs::hkdf(l, &ikm, Some(&salt), &mut altered_info, alg).unwrap(),
                okm
            );

            // Add extra byte to salt
            let mut altered_salt = salt.clone();
            altered_salt.push(1);
            assert_ne!(
                algs::hkdf(l, &ikm, Some(&altered_salt), &mut info, alg).unwrap(),
                okm
            );

            // Wrong ikm
            let mut wrong_ikm = ikm.clone();
            wrong_ikm[0] ^= 0xFF;
            assert_ne!(
                algs::hkdf(l, &wrong_ikm, Some(&salt), &mut info, alg).unwrap(),
                okm
            );
        }
    }
}
