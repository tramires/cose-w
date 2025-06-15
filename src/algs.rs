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
    if alg == EDDSA {
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
            Err(_) => return Err(JsValue::from("Invalid EdDSA Private Key")),
        };
        let signature = priv_key.sign(&content, None);
        s = signature.as_slice().to_vec();
    } else if alg == ES256 {
        let crv = crv.ok_or(JsValue::from("Missing curve"))?;
        use p256::ecdsa::{signature::Signer, SigningKey};
        if crv != keys::P_256 {
            return Err(JsValue::from("Only P_256 curve implemented for ES256"));
        }
        let priv_key = match SigningKey::from_bytes(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid ECDSA Private Key")),
        };
        s = priv_key.sign(&content).to_vec();
    } else if alg == ES256K {
        let crv = crv.ok_or(JsValue::from("Missing curve"))?;
        use k256::ecdsa::{signature::Signer, Signature, SigningKey};
        if crv != keys::SECP256K1 {
            return Err(JsValue::from("Invalid CRV"));
        }
        let priv_key = match SigningKey::from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid ECDSA Private Key")),
        };
        let sig: Signature = priv_key.sign(&content);
        return Ok(sig.to_vec());
    } else if alg == ES384 {
        let crv = crv.ok_or(JsValue::from("Missing curve"))?;
        use p384::ecdsa::{signature::Signer, SigningKey};
        if crv != keys::P_384 {
            return Err(JsValue::from("Only P_384 curve implemented for ES384"));
        }
        let priv_key = match SigningKey::from_bytes(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid ECDSA Private Key")),
        };
        s = priv_key.sign(&content).to_vec();
    } else if alg == ES512 {
        return Err(JsValue::from("ES512 not implemented"));
    } else if [PS256, PS384, PS512].contains(&alg) {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pss::SigningKey;
        use rsa::signature::RandomizedSigner;
        use rsa::signature::SignatureEncoding;
        use rsa::RsaPrivateKey;
        let priv_key = match RsaPrivateKey::from_pkcs1_der(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid RSA Public Key")),
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
    } else {
        return Err(JsValue::from("Invalid Algorithm"));
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
    if alg == EDDSA {
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
            Err(_) => return Err(JsValue::from("Invalid EdDSA Public Key")),
        };
        let sig: Signature = match Signature::from_slice(&signature) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid Signature")),
        };
        v = ec_public_key.verify(&content, &sig).is_ok();
    } else if alg == ES256K {
        use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let crv = crv.ok_or(JsValue::from("Invalid curve"))?;
        if crv != keys::SECP256K1 {
            return Err(JsValue::from("Invalid curve"));
        }
        let pub_key = match VerifyingKey::from_sec1_bytes(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid ECDSA Public Key")),
        };
        let signature: Signature = match Signature::try_from(signature.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid Signature")),
        };
        v = pub_key.verify(content, &signature).is_ok();
    } else if alg == ES256 {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let crv = crv.ok_or(JsValue::from("Invalid curve"))?;
        if crv != keys::P_256 {
            return Err(JsValue::from("Only P_256 curve implemented for ES256"));
        }
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
        let crv = crv.ok_or(JsValue::from("Invalid curve"))?;
        if crv != keys::P_384 {
            return Err(JsValue::from("Only P_384 curve implemented for ES384"));
        }
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
        return Err(JsValue::from("ES512 not implemented"));
    } else if [PS256, PS384, PS512].contains(&alg) {
        use rsa::pkcs8::DecodePublicKey;
        use rsa::pss::{Signature, VerifyingKey};
        use rsa::signature::Verifier;
        use rsa::RsaPublicKey;
        let pub_key = match RsaPublicKey::from_public_key_der(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid RSA Public Key")),
        };
        if alg == PS256 {
            let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(pub_key);
            let signature: Signature = match Signature::try_from(signature.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid Signature")),
            };
            v = verifying_key.verify(&content, &signature).is_ok();
        } else if alg == PS384 {
            let verifying_key: VerifyingKey<Sha384> = VerifyingKey::new(pub_key);
            let signature: Signature = match Signature::try_from(signature.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid Signature")),
            };
            v = verifying_key.verify(&content, &signature).is_ok();
        } else {
            let verifying_key: VerifyingKey<Sha512> = VerifyingKey::new(pub_key);
            let signature: Signature = match Signature::try_from(signature.as_slice()) {
                Ok(v) => v,
                Err(_) => return Err(JsValue::from("Invalid Signature")),
            };
            v = verifying_key.verify(&content, &signature).is_ok();
        }
    } else {
        return Err(JsValue::from("Invalid Algorithm"));
    }
    Ok(v)
}

pub(crate) fn mac(alg: i32, key: &Vec<u8>, content: &Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let mut message_digest;
    let size;
    if alg == HMAC_256_64 {
        let mut mac = match HmacSha256::new_from_slice(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        message_digest = mac.finalize().into_bytes().to_vec();
        size = 8;
    } else if alg == HMAC_256_256 {
        let mut mac = match HmacSha256::new_from_slice(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        message_digest = mac.finalize().into_bytes().to_vec();
        size = 32;
    } else if alg == HMAC_384_384 {
        let mut mac = match HmacSha384::new_from_slice(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        message_digest = mac.finalize().into_bytes().to_vec();
        size = 48;
    } else if alg == HMAC_512_512 {
        let mut mac = match HmacSha512::new_from_slice(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        message_digest = mac.finalize().into_bytes().to_vec();
        size = 64;
    } else if alg == AES_MAC_128_64 {
        let mut mac = match Daa128::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        size = 8;
        message_digest = mac.finalize().into_bytes().to_vec();
    } else if alg == AES_MAC_256_64 {
        let mut mac = match Daa256::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        size = 8;
        message_digest = mac.finalize().into_bytes().to_vec();
    } else if alg == AES_MAC_128_128 {
        let mut mac = match Daa128::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        size = 16;
        message_digest = mac.finalize().into_bytes().to_vec();
    } else if alg == AES_MAC_256_128 {
        let mut mac = match Daa256::new_from_slice(&key) {
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
        let mut mac = match HmacSha256::new_from_slice(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        message_digest = mac.finalize().into_bytes().to_vec();
        size = 8;
    } else if alg == HMAC_256_256 {
        let mut mac = match HmacSha256::new_from_slice(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };

        mac.update(&content);
        message_digest = mac.finalize().into_bytes().to_vec();
        size = 32;
    } else if alg == HMAC_384_384 {
        let mut mac = match HmacSha384::new_from_slice(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        message_digest = mac.finalize().into_bytes().to_vec();
        size = 48;
    } else if alg == HMAC_512_512 {
        let mut mac = match HmacSha512::new_from_slice(key.as_slice()) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        message_digest = mac.finalize().into_bytes().to_vec();
        size = 64;
    } else if alg == AES_MAC_128_64 {
        let mut mac = match Daa128::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        size = 8;
        message_digest = mac.finalize().into_bytes().to_vec();
    } else if alg == AES_MAC_256_64 {
        let mut mac = match Daa256::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        size = 8;
        message_digest = mac.finalize().into_bytes().to_vec();
    } else if alg == AES_MAC_128_128 {
        let mut mac = match Daa128::new_from_slice(&key) {
            Ok(v) => v,
            Err(_) => return Err(JsValue::from("Invalid MAC")),
        };
        mac.update(&content);
        size = 16;
        message_digest = mac.finalize().into_bytes().to_vec();
    } else if alg == AES_MAC_256_128 {
        let mut mac = match Daa256::new_from_slice(&key) {
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
pub(crate) fn rsa_oaep_enc(key: &Vec<u8>, cek: &Vec<u8>, alg: &i32) -> Result<Vec<u8>, JsValue> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::{Oaep, RsaPublicKey};
    let rsa_key = RsaPublicKey::from_public_key_der(key).unwrap();
    if *alg == RSA_OAEP_1 {
        let padding = Oaep::new::<Sha1>();
        let mut rng = rand::thread_rng();

        let out = rsa_key.encrypt(&mut rng, padding, &cek).unwrap();
        Ok(out.to_vec())
    } else if *alg == RSA_OAEP_256 {
        let padding = Oaep::new::<Sha256>();
        let mut rng = rand::thread_rng();

        let out = rsa_key.encrypt(&mut rng, padding, &cek).unwrap();
        Ok(out.to_vec())
    } else if *alg == RSA_OAEP_512 {
        let padding = Oaep::new::<Sha512>();
        let mut rng = rand::thread_rng();

        let out = rsa_key.encrypt(&mut rng, padding, &cek).unwrap();
        Ok(out.to_vec())
    } else {
        return Err(JsValue::from("Invalid alg"));
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
    let rsa_key = RsaPrivateKey::from_pkcs1_der(key).unwrap();
    if *alg == RSA_OAEP_1 {
        let padding = Oaep::new::<Sha1>();
        let out = rsa_key.decrypt(padding, &cek).unwrap();
        Ok(out[..size].to_vec())
    } else if *alg == RSA_OAEP_256 {
        let padding = Oaep::new::<Sha256>();
        let out = rsa_key.decrypt(padding, &cek).unwrap();
        Ok(out[..size].to_vec())
    } else if *alg == RSA_OAEP_512 {
        let padding = Oaep::new::<Sha512>();
        let out = rsa_key.decrypt(padding, &cek).unwrap();
        Ok(out[..size].to_vec())
    } else {
        return Err(JsValue::from("Invalid alg"));
    }
}

pub(crate) fn ecdh_derive_key(
    crv_rec: i32,
    crv_send: i32,
    receiver_key: &Vec<u8>,
    sender_key: &Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    if crv_rec != crv_send {
        return Err("Elliptic Curves don't match".into());
    } else if [keys::X448, keys::X25519].contains(&crv_send) {
        return Err("X448 and X25519 Not implemented".into());
    } else if crv_send == keys::P_256 {
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
    } else if crv_send == keys::P_384 {
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
    } else if crv_send == keys::P_521 {
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
            if alg == DIRECT_HKDF_AES_128 {
                let mut mac = match Daa128::new_from_slice(&ikm) {
                    Ok(v) => v,
                    Err(_) => return Err(JsValue::from("Invalid MAC")),
                };
                mac.update(&padded);
                let s = mac.finalize().into_bytes().to_vec();
                t = s.clone();
                t.truncate(16);
                let mut temp = t.clone();
                okm.append(&mut temp);
            } else {
                let mut mac = match Daa256::new_from_slice(&ikm) {
                    Ok(v) => v,
                    Err(_) => return Err(JsValue::from("Invalid MAC")),
                };
                mac.update(&padded);
                let s = mac.finalize().into_bytes().to_vec();
                t = s.clone();
                t.truncate(16);
                let mut temp = t.clone();
                okm.append(&mut temp);
            }
        }
        return Ok(okm[..length].to_vec());
    }

    let salt = match salt_input {
        Some(v) => Some(v.as_slice()),
        None => None,
    };
    if [ECDH_ES_HKDF_512, ECDH_SS_HKDF_512, DIRECT_HKDF_SHA_512].contains(&alg) {
        let hk = Hkdf::<Sha512>::new(salt, &ikm);
        let mut okm = [0u8; 64];
        match hk.expand(&info_input, &mut okm) {
            Ok(_) => (),
            Err(_) => return Err(JsValue::from("Error during HKDF expand")),
        };
        return Ok(okm[..length as usize].to_vec());
    }
    let hk = Hkdf::<Sha256>::new(salt, &ikm);
    let mut okm = [0u8; 64];
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

pub(crate) fn get_iv_size(alg: &i32) -> Result<usize, JsValue> {
    if [A128GCM, A192GCM, A256GCM, CHACHA20].contains(alg) {
        Ok(12)
    } else if [
        AES_CCM_16_64_128,
        AES_CCM_16_64_256,
        AES_CCM_16_128_256,
        AES_CCM_16_128_256,
    ]
    .contains(alg)
    {
        Ok(13)
    } else if [
        AES_CCM_64_64_128,
        AES_CCM_64_64_256,
        AES_CCM_64_128_256,
        AES_CCM_64_128_256,
    ]
    .contains(alg)
    {
        Ok(7)
    } else {
        Err(JsValue::from("Invalid Algorithm"))
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
