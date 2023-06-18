use crate::algs;
use crate::cbor::Encoder;
use wasm_bindgen::prelude::*;

pub(crate) const MAC: &str = "MAC";
pub(crate) const MAC0: &str = "MAC0";
const MAC_ALL: [&str; 2] = [MAC, MAC0];
const MAC_STRUCT_LEN: usize = 4;

pub(crate) fn gen_mac(
    key: &Vec<u8>,
    alg: &i32,
    aead: &Vec<u8>,
    context: &str,
    body_protected: &Vec<u8>,
    payload: &Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let mut e = Encoder::new();
    if MAC_ALL.contains(&context) {
        e.array(MAC_STRUCT_LEN);
        e.text(context);
        e.bytes(body_protected.as_slice());
        e.bytes(aead.as_slice());
        e.bytes(payload.as_slice());
        algs::mac(*alg, &key, &e.encoded())
    } else {
        Err(JsValue::from("Invalid Context"))
    }
}

pub(crate) fn verify_mac(
    key: &Vec<u8>,
    alg: &i32,
    aead: &Vec<u8>,
    context: &str,
    body_protected: &Vec<u8>,
    tag: &Vec<u8>,
    payload: &Vec<u8>,
) -> Result<bool, JsValue> {
    let mut e = Encoder::new();
    if MAC_ALL.contains(&context) {
        e.array(MAC_STRUCT_LEN);
        e.text(context);
        e.bytes(body_protected.as_slice());
        e.bytes(aead.as_slice());
        e.bytes(payload.as_slice());
        algs::mac_verify(*alg, &key, &e.encoded(), &tag)
    } else {
        Err(JsValue::from("Invalid Context"))
    }
}
