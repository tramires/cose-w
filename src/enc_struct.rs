use crate::algs;
use crate::cbor::Encoder;
use wasm_bindgen::prelude::*;

pub(crate) const ENCRYPT: &str = "Encrypt";
pub(crate) const ENCRYPT0: &str = "Encrypt0";
pub(crate) const ENCRYPT_RECIPIENT: &str = "Enc_Recipient";
pub(crate) const MAC_RECIPIENT: &str = "Mac_Recipient";
pub(crate) const REC_RECIPIENT: &str = "Rec_Recipient";

const ENC_ALL: [&str; 5] = [
    ENCRYPT,
    ENCRYPT0,
    ENCRYPT_RECIPIENT,
    MAC_RECIPIENT,
    REC_RECIPIENT,
];
const ENC_STRUCT_LEN: usize = 3;

pub(crate) fn gen_cipher(
    key: &Vec<u8>,
    alg: &i32,
    iv: &Vec<u8>,
    aead: &Vec<u8>,
    context: &str,
    body_protected: &Vec<u8>,
    payload: &Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let mut e = Encoder::new();
    if ENC_ALL.contains(&context) {
        e.array(ENC_STRUCT_LEN);
        e.text(context);
        e.bytes(body_protected.as_slice());
        e.bytes(aead.as_slice());
        algs::encrypt(*alg, &key, &iv, &payload, &e.encoded())
    } else {
        Err(JsValue::from("Invalid Context"))
    }
}

pub(crate) fn dec_cipher(
    key: &Vec<u8>,
    alg: &i32,
    iv: &Vec<u8>,
    aead: &Vec<u8>,
    context: &str,
    body_protected: &Vec<u8>,
    ciphertext: &Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let mut e = Encoder::new();
    if ENC_ALL.contains(&context) {
        e.array(ENC_STRUCT_LEN);
        e.text(context);
        e.bytes(body_protected.as_slice());
        e.bytes(aead.as_slice());
        algs::decrypt(*alg, &key, &iv, &ciphertext, &e.encoded())
    } else {
        Err(JsValue::from("Invalid Context"))
    }
}
