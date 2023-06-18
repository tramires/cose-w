use crate::algs;
use crate::keys;
use wasm_bindgen::JsValue;

pub const ENC0_TAG: u32 = 16;
pub const MAC0_TAG: u32 = 17;
pub const SIG1_TAG: u32 = 18;
pub const ENC_TAG: u32 = 96;
pub const MAC_TAG: u32 = 97;
pub const SIG_TAG: u32 = 98;

pub const ENC0_TYPE: &str = "cose-encrypt0";
pub const MAC0_TYPE: &str = "cose-mac0";
pub const SIG1_TYPE: &str = "cose-sign1";
pub const ENC_TYPE: &str = "cose-encrypt";
pub const MAC_TYPE: &str = "cose-mac";
pub const SIG_TYPE: &str = "cose-sign";

pub(crate) fn get_alg_id(alg: &str) -> Result<i32, JsValue> {
    for i in 0..algs::SIGNING_ALGS.len() {
        if algs::SIGNING_ALGS_NAMES[i] == alg {
            return Ok(algs::SIGNING_ALGS[i]);
        }
    }
    for i in 0..algs::ENCRYPT_ALGS.len() {
        if algs::ENCRYPT_ALGS_NAMES[i] == alg {
            return Ok(algs::ENCRYPT_ALGS[i]);
        }
    }
    for i in 0..algs::MAC_ALGS.len() {
        if algs::MAC_ALGS_NAMES[i] == alg {
            return Ok(algs::MAC_ALGS[i]);
        }
    }
    for i in 0..algs::KEY_DISTRIBUTION_ALGS.len() {
        if algs::KEY_DISTRIBUTION_NAMES[i] == alg {
            return Ok(algs::KEY_DISTRIBUTION_ALGS[i]);
        }
    }
    Err("Invalid Algorithm".into())
}
pub(crate) fn get_kty_id(kty: &str) -> Result<i32, JsValue> {
    for i in 0..keys::KTY_ALL.len() {
        if keys::KTY_NAMES[i] == kty {
            return Ok(keys::KTY_ALL[i]);
        }
    }
    return Err("Invalid kty parameter".into());
}
pub(crate) fn get_crv_id(crv: &str) -> Result<i32, JsValue> {
    for i in 0..keys::CURVES_ALL.len() {
        if keys::CURVES_NAMES[i] == crv {
            return Ok(keys::CURVES_ALL[i]);
        }
    }
    return Err("Invalid crv parameter".into());
}
pub(crate) fn get_key_op_id(key_op: &str) -> Result<i32, JsValue> {
    for i in 0..keys::KEY_OPS_ALL.len() {
        if keys::KEY_OPS_NAMES[i] == key_op {
            return Ok(keys::KEY_OPS_ALL[i]);
        }
    }
    return Err("Invalid key op parameter".into());
}
