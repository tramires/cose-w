use crate::algs;
use crate::cbor::Encoder;
use wasm_bindgen::prelude::*;

pub(crate) const SIGNATURE: &str = "Signature";
pub(crate) const SIGNATURE1: &str = "Signature1";
pub(crate) const COUNTER_SIGNATURE: &str = "CounterSignature";

const SIGNATURE1_LEN: usize = 4;
const SIGNATURE_LEN: usize = 5;
const COUNTER_SIGNATURE_LEN: usize = 5;

pub(crate) fn gen_sig(
    key: &Vec<u8>,
    alg: &i32,
    external_aad: &Vec<u8>,
    context: &str,
    body_protected: &Vec<u8>,
    sign_protected: &Vec<u8>,
    payload: &Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let mut e = Encoder::new();
    if context == SIGNATURE {
        e.array(SIGNATURE_LEN);
        e.text(SIGNATURE);
        e.bytes(body_protected.as_slice());
        e.bytes(sign_protected.as_slice());
    } else if context == SIGNATURE1 {
        e.array(SIGNATURE1_LEN);
        e.text(SIGNATURE1);
        e.bytes(body_protected.as_slice());
    } else if context == COUNTER_SIGNATURE {
        e.array(COUNTER_SIGNATURE_LEN);
        e.text(COUNTER_SIGNATURE);
        e.bytes(body_protected.as_slice());
        e.bytes(sign_protected.as_slice());
    } else {
        return Err(JsValue::from("Invalid Context"));
    }
    e.bytes(external_aad.as_slice());
    e.bytes(payload.as_slice());
    algs::sign(*alg, &key, &e.encoded())
}

pub(crate) fn get_to_sign(
    external_aad: &Vec<u8>,
    context: &str,
    body_protected: &Vec<u8>,
    sign_protected: &Vec<u8>,
    payload: &Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let mut e = Encoder::new();
    if context == SIGNATURE {
        e.array(SIGNATURE_LEN);
        e.text(SIGNATURE);
        e.bytes(body_protected.as_slice());
        e.bytes(sign_protected.as_slice());
    } else if context == SIGNATURE1 {
        e.array(SIGNATURE1_LEN);
        e.text(SIGNATURE1);
        e.bytes(body_protected.as_slice());
    } else if context == COUNTER_SIGNATURE {
        e.array(COUNTER_SIGNATURE_LEN);
        e.text(COUNTER_SIGNATURE);
        e.bytes(body_protected.as_slice());
        e.bytes(sign_protected.as_slice());
    } else {
        return Err(JsValue::from("Invalid Context"));
    }
    e.bytes(external_aad.as_slice());
    e.bytes(payload.as_slice());
    Ok(e.encoded())
}
pub(crate) fn verify_sig(
    key: &Vec<u8>,
    alg: &i32,
    external_aad: &Vec<u8>,
    context: &str,
    body_protected: &Vec<u8>,
    sign_protected: &Vec<u8>,
    payload: &Vec<u8>,
    signature: &Vec<u8>,
) -> Result<bool, JsValue> {
    let mut e = Encoder::new();
    if context == SIGNATURE {
        e.array(SIGNATURE_LEN);
        e.text(SIGNATURE);
        e.bytes(body_protected.as_slice());
        e.bytes(sign_protected.as_slice());
    } else if context == SIGNATURE1 {
        e.array(SIGNATURE1_LEN);
        e.text(SIGNATURE1);
        e.bytes(body_protected.as_slice());
    } else if context == COUNTER_SIGNATURE {
        e.array(COUNTER_SIGNATURE_LEN);
        e.text(COUNTER_SIGNATURE);
        e.bytes(body_protected.as_slice());
        e.bytes(sign_protected.as_slice());
    } else {
        return Err(JsValue::from("Invalid Context"));
    }
    e.bytes(external_aad.as_slice());
    e.bytes(payload.as_slice());
    Ok(algs::verify(*alg, &key, &e.encoded(), &signature).unwrap())
}
