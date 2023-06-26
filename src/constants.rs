use crate::algs;
use crate::keys;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Alg;

#[wasm_bindgen]
impl Alg {
    #[wasm_bindgen(getter)]
    pub fn es256() -> i32 {
        algs::ES256
    }
    #[wasm_bindgen(getter)]
    pub fn es256k() -> i32 {
        algs::ES256K
    }
    #[wasm_bindgen(getter)]
    pub fn es384() -> i32 {
        algs::ES384
    }
    #[wasm_bindgen(getter)]
    pub fn es512() -> i32 {
        algs::ES512
    }
    #[wasm_bindgen(getter)]
    pub fn eddsa() -> i32 {
        algs::EDDSA
    }
    #[wasm_bindgen(getter)]
    pub fn ps256() -> i32 {
        algs::PS256
    }
    #[wasm_bindgen(getter)]
    pub fn ps384() -> i32 {
        algs::PS384
    }
    #[wasm_bindgen(getter)]
    pub fn ps512() -> i32 {
        algs::PS512
    }
    #[wasm_bindgen(getter)]
    pub fn sha_256() -> i32 {
        algs::SHA_256
    }
    #[wasm_bindgen(getter)]
    pub fn a128gcm() -> i32 {
        algs::A128GCM
    }
    #[wasm_bindgen(getter)]
    pub fn a192gcm() -> i32 {
        algs::A192GCM
    }
    #[wasm_bindgen(getter)]
    pub fn a256gcm() -> i32 {
        algs::A256GCM
    }
    #[wasm_bindgen(getter)]
    pub fn chacha20() -> i32 {
        algs::CHACHA20
    }
    #[wasm_bindgen(getter)]
    pub fn aes_ccm_16_64_128() -> i32 {
        algs::AES_CCM_16_64_128
    }
    #[wasm_bindgen(getter)]
    pub fn aes_ccm_16_64_256() -> i32 {
        algs::AES_CCM_16_64_256
    }
    #[wasm_bindgen(getter)]
    pub fn aes_ccm_64_64_128() -> i32 {
        algs::AES_CCM_64_64_128
    }
    #[wasm_bindgen(getter)]
    pub fn hmac_256_64() -> i32 {
        algs::HMAC_256_64
    }
    #[wasm_bindgen(getter)]
    pub fn hmac_256_256() -> i32 {
        algs::HMAC_256_256
    }
    #[wasm_bindgen(getter)]
    pub fn hmac_384_384() -> i32 {
        algs::HMAC_384_384
    }
    #[wasm_bindgen(getter)]
    pub fn hmac_512_512() -> i32 {
        algs::HMAC_512_512
    }
    #[wasm_bindgen(getter)]
    pub fn aes_mac_128_64() -> i32 {
        algs::AES_MAC_128_64
    }
    #[wasm_bindgen(getter)]
    pub fn aes_mac_256_64() -> i32 {
        algs::AES_MAC_256_64
    }
    #[wasm_bindgen(getter)]
    pub fn aes_mac_128_128() -> i32 {
        algs::AES_MAC_128_128
    }
    #[wasm_bindgen(getter)]
    pub fn aes_mac_256_128() -> i32 {
        algs::AES_MAC_256_128
    }
    #[wasm_bindgen(getter)]
    pub fn direct() -> i32 {
        algs::DIRECT
    }
    #[wasm_bindgen(getter)]
    pub fn direct_hkdf_sha_256() -> i32 {
        algs::DIRECT_HKDF_SHA_256
    }
    #[wasm_bindgen(getter)]
    pub fn direct_hkdf_sha_512() -> i32 {
        algs::DIRECT_HKDF_SHA_512
    }
    #[wasm_bindgen(getter)]
    pub fn direct_hkdf_aes_128() -> i32 {
        algs::DIRECT_HKDF_AES_128
    }
    #[wasm_bindgen(getter)]
    pub fn direct_hkdf_aes_256() -> i32 {
        algs::DIRECT_HKDF_AES_256
    }
    #[wasm_bindgen(getter)]
    pub fn a128kw() -> i32 {
        algs::A128KW
    }
    #[wasm_bindgen(getter)]
    pub fn a192kw() -> i32 {
        algs::A192KW
    }
    #[wasm_bindgen(getter)]
    pub fn a256kw() -> i32 {
        algs::A256KW
    }
    #[wasm_bindgen(getter)]
    pub fn ecdh_es_hkdf_256() -> i32 {
        algs::ECDH_ES_HKDF_256
    }
    #[wasm_bindgen(getter)]
    pub fn ecdh_es_hkdf_512() -> i32 {
        algs::ECDH_ES_HKDF_512
    }
    #[wasm_bindgen(getter)]
    pub fn ecdh_ss_hkdf_256() -> i32 {
        algs::ECDH_SS_HKDF_256
    }
    #[wasm_bindgen(getter)]
    pub fn ecdh_ss_hkdf_512() -> i32 {
        algs::ECDH_SS_HKDF_512
    }
    #[wasm_bindgen(getter)]
    pub fn ecdh_es_a128kw() -> i32 {
        algs::ECDH_ES_A128KW
    }
    #[wasm_bindgen(getter)]
    pub fn ecdh_es_a192kw() -> i32 {
        algs::ECDH_ES_A192KW
    }
    #[wasm_bindgen(getter)]
    pub fn ecdh_es_a256kw() -> i32 {
        algs::ECDH_ES_A256KW
    }
    #[wasm_bindgen(getter)]
    pub fn ecdh_ss_a128kw() -> i32 {
        algs::ECDH_SS_A128KW
    }
    #[wasm_bindgen(getter)]
    pub fn ecdh_ss_a192kw() -> i32 {
        algs::ECDH_SS_A192KW
    }
    #[wasm_bindgen(getter)]
    pub fn ecdh_ss_a256kw() -> i32 {
        algs::ECDH_SS_A256KW
    }
}

#[wasm_bindgen]
pub struct Kty;

#[wasm_bindgen]
impl Kty {
    #[wasm_bindgen(getter)]
    pub fn okp() -> i32 {
        keys::OKP
    }
    #[wasm_bindgen(getter)]
    pub fn ec2() -> i32 {
        keys::EC2
    }
    #[wasm_bindgen(getter)]
    pub fn rsa() -> i32 {
        keys::RSA
    }
    #[wasm_bindgen(getter)]
    pub fn symmetric() -> i32 {
        keys::SYMMETRIC
    }
    #[wasm_bindgen(getter)]
    pub fn reserved() -> i32 {
        keys::RESERVED
    }
}

#[wasm_bindgen]
pub struct Crv;

#[wasm_bindgen]
impl Crv {
    #[wasm_bindgen(getter)]
    pub fn p_256() -> i32 {
        keys::P_256
    }
    #[wasm_bindgen(getter)]
    pub fn secp256k1() -> i32 {
        keys::SECP256K1
    }
    #[wasm_bindgen(getter)]
    pub fn p_384() -> i32 {
        keys::P_384
    }
    #[wasm_bindgen(getter)]
    pub fn p_521() -> i32 {
        keys::P_521
    }
    #[wasm_bindgen(getter)]
    pub fn x25519() -> i32 {
        keys::X25519
    }
    #[wasm_bindgen(getter)]
    pub fn x448() -> i32 {
        keys::X448
    }
    #[wasm_bindgen(getter)]
    pub fn ed25519() -> i32 {
        keys::ED25519
    }
    #[wasm_bindgen(getter)]
    pub fn ed448() -> i32 {
        keys::ED448
    }
}

#[wasm_bindgen]
pub struct KeyOp;

#[wasm_bindgen]
impl KeyOp {
    #[wasm_bindgen(getter)]
    pub fn sign() -> i32 {
        keys::KEY_OPS_SIGN
    }
    #[wasm_bindgen(getter)]
    pub fn verify() -> i32 {
        keys::KEY_OPS_VERIFY
    }
    #[wasm_bindgen(getter)]
    pub fn encrypt() -> i32 {
        keys::KEY_OPS_ENCRYPT
    }
    #[wasm_bindgen(getter)]
    pub fn decrypt() -> i32 {
        keys::KEY_OPS_DECRYPT
    }
    #[wasm_bindgen(getter)]
    pub fn wrap() -> i32 {
        keys::KEY_OPS_WRAP
    }
    #[wasm_bindgen(getter)]
    pub fn unwrap() -> i32 {
        keys::KEY_OPS_UNWRAP
    }
    #[wasm_bindgen(getter)]
    pub fn derive() -> i32 {
        keys::KEY_OPS_DERIVE
    }
    #[wasm_bindgen(getter)]
    pub fn derive_bits() -> i32 {
        keys::KEY_OPS_DERIVE_BITS
    }
    #[wasm_bindgen(getter)]
    pub fn mac() -> i32 {
        keys::KEY_OPS_MAC
    }
    #[wasm_bindgen(getter)]
    pub fn mac_verify() -> i32 {
        keys::KEY_OPS_MAC_VERIFY
    }
}
