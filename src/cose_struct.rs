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
    crv: &Option<i32>,
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
    algs::sign(*alg, *crv, &key, &e.encoded())
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
    crv: &Option<i32>,
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
    Ok(algs::verify(*alg, *crv, &key, &e.encoded(), &signature)?)
}

pub(crate) const MAC: &str = "MAC";
pub(crate) const MAC0: &str = "MAC0";
const MAC_ALL: [&str; 2] = [MAC, MAC0, MAC_RECIPIENT];
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
pub(crate) const ENCRYPT: &str = "Encrypt";
pub(crate) const ENCRYPT0: &str = "Encrypt0";
pub(crate) const ENCRYPT_RECIPIENT: &str = "Enc_Recipient";
pub(crate) const MAC_RECIPIENT: &str = "Mac_Recipient";
pub(crate) const REC_RECIPIENT: &str = "Rec_Recipient";

const ENC_ALL: [&str; 4] = [ENCRYPT, ENCRYPT0, ENCRYPT_RECIPIENT, REC_RECIPIENT];
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
const STRUCT_LEN: usize = 5;
const PARTY_STRUCT_LEN: usize = 3;
const SUPP_PUB_STRUCT_LEN: usize = 3;

pub(crate) fn gen_kdf(
    alg: &i32,
    party_u_identity: &Option<Vec<u8>>,
    party_u_nonce: &Option<Vec<u8>>,
    party_u_other: &Option<Vec<u8>>,
    party_v_identity: &Option<Vec<u8>>,
    party_v_nonce: &Option<Vec<u8>>,
    party_v_other: &Option<Vec<u8>>,
    key_data_len: u16,
    protected: &Vec<u8>,
    other: &Option<Vec<u8>>,
    supp_priv_info: &Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    let mut e = Encoder::new();
    if *supp_priv_info == None {
        e.array(STRUCT_LEN - 1);
    } else {
        e.array(STRUCT_LEN);
    }
    e.signed(*alg);
    e.array(PARTY_STRUCT_LEN);
    if *party_u_identity == None {
        e.null();
    } else {
        e.bytes(&party_u_identity.as_ref().unwrap());
    }
    if *party_u_nonce == None {
        e.null();
    } else {
        e.bytes(&party_u_nonce.as_ref().unwrap());
    }
    if *party_u_other == None {
        e.null();
    } else {
        e.bytes(&party_u_other.as_ref().unwrap());
    }
    e.array(PARTY_STRUCT_LEN);
    if *party_v_identity == None {
        e.null();
    } else {
        e.bytes(&party_v_identity.as_ref().unwrap());
    }
    if *party_v_nonce == None {
        e.null();
    } else {
        e.bytes(&party_v_nonce.as_ref().unwrap());
    }
    if *party_v_other == None {
        e.null();
    } else {
        e.bytes(&party_v_other.as_ref().unwrap());
    }
    if *other == None {
        e.array(SUPP_PUB_STRUCT_LEN - 1);
    } else {
        e.array(SUPP_PUB_STRUCT_LEN);
    }
    e.unsigned(key_data_len.into());
    e.bytes(&protected);
    if *other != None {
        e.bytes(&other.as_ref().unwrap());
    }
    if *supp_priv_info != None {
        e.bytes(&supp_priv_info.as_ref().unwrap());
    }
    Ok(e.encoded())
}
