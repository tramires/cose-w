use crate::algs;
use crate::cbor::{Decoder, Encoder};
use crate::enc_struct;
use crate::headers;
use crate::kdf_struct;
use crate::keys;
use crate::sig_struct;
use wasm_bindgen::prelude::*;

#[derive(Clone)]
#[wasm_bindgen]
pub struct CoseAgent {
    pub(crate) header: headers::CoseHeader,
    pub(crate) payload: Vec<u8>,
    pub(crate) ph_bstr: Vec<u8>,
    pub(crate) pub_key: Vec<u8>,
    pub(crate) s_key: Vec<u8>,
    pub(crate) context: String,
    pub(crate) crv: Option<i32>,
    pub(crate) key_ops: Vec<i32>,
}

const KEY_OPS_SKEY: [i32; 8] = [
    keys::KEY_OPS_DERIVE_BITS,
    keys::KEY_OPS_DERIVE,
    keys::KEY_OPS_DECRYPT,
    keys::KEY_OPS_ENCRYPT,
    keys::KEY_OPS_MAC,
    keys::KEY_OPS_MAC_VERIFY,
    keys::KEY_OPS_WRAP,
    keys::KEY_OPS_UNWRAP,
];

const SIZE: usize = 3;
#[wasm_bindgen]
impl CoseAgent {
    #[wasm_bindgen(constructor)]
    pub fn new() -> CoseAgent {
        CoseAgent {
            header: headers::CoseHeader::new(),
            payload: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            key_ops: Vec::new(),
            s_key: Vec::new(),
            crv: None,
            context: "".to_string(),
        }
    }

    pub fn new_counter_sig() -> CoseAgent {
        CoseAgent {
            header: headers::CoseHeader::new(),
            payload: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            key_ops: Vec::new(),
            s_key: Vec::new(),
            crv: None,
            context: sig_struct::COUNTER_SIGNATURE.to_string(),
        }
    }

    pub fn add_header(&mut self, header: headers::CoseHeader) {
        self.header = header;
    }

    pub fn key(&mut self, key: &keys::CoseKey) -> Result<(), JsValue> {
        let alg = self.header.alg.ok_or(JsValue::from("Missing Header alg"))?;
        key.verify_kty()?;
        if algs::ECDH_ALGS.contains(&alg) {
            if !keys::ECDH_KTY.contains(key.kty.as_ref().ok_or(JsValue::from("Missing kty"))?) {
                return Err(JsValue::from("Invalid kty"));
            }
        } else if (alg != algs::DIRECT && !algs::A_KW.contains(&alg))
            && key.alg.ok_or(JsValue::from("Missing Key alg"))? != alg
        {
            return Err(JsValue::from("Header and Key algs don't match"));
        }

        if algs::SIGNING_ALGS.contains(&alg) {
            if key.key_ops.contains(&keys::KEY_OPS_SIGN) {
                self.s_key = key.get_s_key()?;
            }
            if key.key_ops.contains(&keys::KEY_OPS_VERIFY) {
                self.pub_key = key.get_pub_key(alg)?;
            }
        } else if algs::KEY_DISTRIBUTION_ALGS.contains(&alg) || algs::ENCRYPT_ALGS.contains(&alg) {
            if KEY_OPS_SKEY.iter().any(|i| key.key_ops.contains(i)) {
                self.s_key = key.get_s_key()?;
            }
            if algs::ECDH_ALGS.contains(&alg) {
                if key.key_ops.len() == 0 {
                    self.pub_key = key.get_pub_key(alg)?;
                }
            }
        }
        self.crv = key.crv;
        self.key_ops = key.key_ops.clone();
        Ok(())
    }

    pub(crate) fn enc(
        &mut self,
        content: &Vec<u8>,
        external_aad: &Vec<u8>,
        body_protected: &Vec<u8>,
        alg: &i32,
        iv: &Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        if !self.key_ops.contains(&keys::KEY_OPS_ENCRYPT) {
            return Err(JsValue::from("Missing Key key_ops_encrypt"));
        }
        Ok(enc_struct::gen_cipher(
            &self.s_key,
            alg,
            iv,
            &external_aad,
            &self.context,
            &body_protected,
            &content,
        )?)
    }
    pub(crate) fn dec(
        &self,
        content: &Vec<u8>,
        external_aad: &Vec<u8>,
        body_protected: &Vec<u8>,
        alg: &i32,
        iv: &Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        if !self.key_ops.contains(&keys::KEY_OPS_DECRYPT) {
            return Err(JsValue::from("Missing Key key_ops_decrypt"));
        }
        Ok(enc_struct::dec_cipher(
            &self.s_key,
            alg,
            iv,
            &external_aad,
            &self.context,
            &body_protected,
            &content,
        )?)
    }

    pub(crate) fn sign(
        &mut self,
        content: &Vec<u8>,
        external_aad: &Vec<u8>,
        body_protected: &Vec<u8>,
    ) -> Result<(), JsValue> {
        self.ph_bstr = self.header.get_protected_bstr(false)?;
        if !self.key_ops.contains(&keys::KEY_OPS_SIGN) {
            return Err(JsValue::from("Missing Key key_ops_sign"));
        }
        self.payload = sig_struct::gen_sig(
            &self.s_key,
            &self.header.alg.ok_or(JsValue::from("Missing alg"))?,
            &external_aad,
            &self.context,
            &body_protected,
            &self.ph_bstr,
            &content,
        )?;
        Ok(())
    }
    pub(crate) fn verify(
        &self,
        content: &Vec<u8>,
        external_aad: &Vec<u8>,
        body_protected: &Vec<u8>,
    ) -> Result<bool, JsValue> {
        if !self.key_ops.contains(&keys::KEY_OPS_VERIFY) {
            return Err(JsValue::from("Missing Key key_ops_verify"));
        }
        Ok(sig_struct::verify_sig(
            &self.pub_key,
            &self.header.alg.ok_or(JsValue::from("Missing alg"))?,
            &external_aad,
            &self.context,
            &body_protected,
            &self.ph_bstr,
            &content,
            &self.payload,
        )?)
    }

    pub fn add_signature(&mut self, signature: Vec<u8>) -> Result<(), JsValue> {
        if self.context != sig_struct::COUNTER_SIGNATURE {
            return Err("Method only available for COUNTER_SIGNATURE context".into());
        }
        self.payload = signature;
        Ok(())
    }

    pub(crate) fn get_to_sign(
        &mut self,
        content: &Vec<u8>,
        external_aad: &Vec<u8>,
        body_protected: &Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        if self.context != sig_struct::COUNTER_SIGNATURE {
            return Err("Method only available for COUNTER_SIGNATURE context".into());
        }
        self.ph_bstr = self.header.get_protected_bstr(false)?;
        sig_struct::get_to_sign(
            &external_aad,
            sig_struct::COUNTER_SIGNATURE,
            &body_protected,
            &self.ph_bstr,
            &content,
        )
    }

    pub(crate) fn derive_key(
        &mut self,
        cek: &Vec<u8>,
        size: usize,
        sender: bool,
        true_alg: &i32,
    ) -> Result<Vec<u8>, JsValue> {
        if self.ph_bstr.len() <= 0 {
            self.ph_bstr = self.header.get_protected_bstr(false)?;
        }
        let alg = self.header.alg.ok_or(JsValue::from("Missing alg"))?;
        if algs::A_KW.contains(&alg) {
            if sender {
                self.payload = algs::aes_key_wrap(&self.s_key, alg, &cek)?;
            } else {
                return Ok(algs::aes_key_unwrap(&self.s_key, alg, &cek)?);
            }
            return Ok(cek.to_vec());
        } else if algs::D_HA.contains(&alg) {
            return Err(JsValue::from("DIRECT HKDF AES-128/AES-256 not implemented"));
        } else if algs::D_HS.contains(&alg) {
            if self.header.party_u_nonce == None && self.header.salt == None {
                return Err(JsValue::from("Party U Nonce or salt required"));
            }
            let mut kdf_context = kdf_struct::gen_kdf(
                true_alg,
                &self.header.party_u_identity,
                &self.header.party_u_nonce,
                &self.header.party_u_other,
                &self.header.party_v_identity,
                &self.header.party_v_nonce,
                &self.header.party_v_other,
                size as u16 * 8,
                &self.ph_bstr,
                None,
                None,
            )?;
            return Ok(algs::hkdf(
                size,
                &self.s_key,
                self.header.salt.as_ref(),
                &mut kdf_context,
                alg,
            )?);
        } else if algs::ECDH_H.contains(&alg) {
            let (receiver_key, sender_key, crv_rec, crv_send);
            if sender {
                if self.pub_key.len() <= 0 {
                    return Err(JsValue::from("Missing receiver public key"));
                }
                receiver_key = self.pub_key.clone();
                sender_key = self.header.ecdh_key.get_s_key()?;
                crv_rec = self.crv.ok_or(JsValue::from("Missing crv"))?;

                crv_send = self
                    .header
                    .ecdh_key
                    .crv
                    .ok_or(JsValue::from("Missing crv"))?;
            } else {
                if self.s_key.len() <= 0 {
                    return Err(JsValue::from("Missing receiver private key"));
                }
                receiver_key = self.header.ecdh_key.get_pub_key(alg)?;
                sender_key = self.s_key.clone();
                crv_send = self.crv.ok_or(JsValue::from("Missing crv"))?;

                crv_rec = self
                    .header
                    .ecdh_key
                    .crv
                    .ok_or(JsValue::from("Missing crv"))?;
            }
            let shared = algs::ecdh_derive_key(&crv_rec, &crv_send, &receiver_key, &sender_key)?;

            let mut kdf_context = kdf_struct::gen_kdf(
                true_alg,
                &self.header.party_u_identity,
                &self.header.party_u_nonce,
                &self.header.party_u_other,
                &self.header.party_v_identity,
                &self.header.party_v_nonce,
                &self.header.party_v_other,
                size as u16 * 8,
                &self.ph_bstr,
                None,
                None,
            )?;
            return Ok(algs::hkdf(
                size,
                &shared,
                self.header.salt.as_ref(),
                &mut kdf_context,
                alg,
            )?);
        } else if algs::ECDH_A.contains(&alg) {
            let (receiver_key, sender_key, crv_rec, crv_send);
            if sender {
                if self.pub_key.len() <= 0 {
                    return Err(JsValue::from("Missing receiver public key"));
                }
                receiver_key = self.pub_key.clone();
                sender_key = self.header.ecdh_key.get_s_key()?;
                crv_rec = self.crv.ok_or(JsValue::from("Missing crv"))?;

                crv_send = self
                    .header
                    .ecdh_key
                    .crv
                    .ok_or(JsValue::from("Missing crv"))?;
            } else {
                if self.s_key.len() <= 0 {
                    return Err(JsValue::from("Missing receiver private key"));
                }
                receiver_key = self.header.ecdh_key.get_pub_key(alg)?;
                sender_key = self.s_key.clone();
                crv_send = self.crv.ok_or(JsValue::from("Missing crv"))?;

                crv_rec = self
                    .header
                    .ecdh_key
                    .crv
                    .ok_or(JsValue::from("Missing crv"))?;
            }
            let shared = algs::ecdh_derive_key(&crv_rec, &crv_send, &receiver_key, &sender_key)?;
            let size_a = algs::get_cek_size(&alg)?;
            let alg_a;
            if [algs::ECDH_ES_A128KW, algs::ECDH_SS_A128KW].contains(&alg) {
                alg_a = algs::A128KW;
            } else if [algs::ECDH_ES_A192KW, algs::ECDH_SS_A192KW].contains(&alg) {
                alg_a = algs::A192KW;
            } else {
                alg_a = algs::A256KW;
            }

            let mut kdf_context = kdf_struct::gen_kdf(
                &alg_a,
                &self.header.party_u_identity,
                &self.header.party_u_nonce,
                &self.header.party_u_other,
                &self.header.party_v_identity,
                &self.header.party_v_nonce,
                &self.header.party_v_other,
                size_a as u16 * 8,
                &self.ph_bstr,
                None,
                None,
            )?;
            let kek = algs::hkdf(
                size_a,
                &shared,
                self.header.salt.as_ref(),
                &mut kdf_context,
                alg,
            )?;
            if sender {
                self.payload = algs::aes_key_wrap(&kek, alg_a, &cek)?;
            } else {
                return Ok(algs::aes_key_unwrap(&kek, alg_a, &cek)?);
            }
            return Ok(cek.to_vec());
        } else {
            return Err(JsValue::from("Invalid alg"));
        }
    }

    pub(crate) fn decode(&mut self, d: &mut Decoder) -> Result<(), JsValue> {
        if self.ph_bstr.len() > 0 {
            self.header.decode_protected_bstr(self.ph_bstr.clone())?;
        }
        self.header.decode_unprotected(d, true)?;
        self.payload = d.bytes()?;
        Ok(())
    }

    pub(crate) fn encode(&mut self, e: &mut Encoder) -> Result<(), JsValue> {
        e.array(SIZE);
        e.bytes(&self.ph_bstr);
        self.header.encode_unprotected(e)?;
        e.bytes(&self.payload);
        Ok(())
    }
}
