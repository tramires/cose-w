use crate::algs;
use crate::cbor::{Decoder, Encoder};
use crate::cose_struct;
use crate::headers;
use crate::keys;
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
    pub(crate) base_iv: Option<Vec<u8>>,
    pub(crate) enc: bool,
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
            base_iv: None,
            enc: false,
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
            base_iv: None,
            enc: false,
            context: cose_struct::COUNTER_SIGNATURE.to_string(),
        }
    }
    #[wasm_bindgen(getter)]
    pub fn header(&self) -> headers::CoseHeader {
        self.header.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }
    pub fn set_header(&mut self, header: headers::CoseHeader) {
        self.header = header;
    }
    pub fn ephemeral_key(&mut self, key: keys::CoseKey, prot: bool, crit: bool) {
        self.header.ephemeral_key(key, prot, crit);
    }
    pub fn static_key(&mut self, key: keys::CoseKey, prot: bool, crit: bool) {
        self.header.static_key(key, prot, crit);
    }
    pub fn set_static_kid(&mut self, kid: Vec<u8>, key: keys::CoseKey, prot: bool, crit: bool) {
        self.header.set_static_kid(kid, key, prot, crit);
    }

    pub fn key(&mut self, key: &keys::CoseKey) -> Result<(), JsValue> {
        let alg = self.header.alg.ok_or(JsValue::from("Missing algorithm"))?;
        key.verify_kty()?;
        if algs::ECDH_ALGS.contains(&alg) {
            if !keys::ECDH_KTY.contains(key.kty.as_ref().ok_or(JsValue::from("Missing KTY"))?) {
                return Err(JsValue::from("Invalid KTY"));
            }
            if key.alg != None {
                if key.alg.ok_or(JsValue::from("Missing algorithm"))? != alg {
                    return Err(JsValue::from("Algorithms dont match"));
                }
            }
        } else if (alg != algs::DIRECT
            && !algs::A_KW.contains(&alg)
            && !algs::RSA_OAEP.contains(&alg))
            && key.alg.ok_or(JsValue::from("Missing algorithm"))? != alg
        {
            return Err(JsValue::from("Algorithms dont match"));
        }
        if algs::SIGNING_ALGS.contains(&alg) {
            if key.key_ops.contains(&keys::KEY_OPS_SIGN) {
                self.s_key = key.get_s_key()?;
            }
            if key.key_ops.contains(&keys::KEY_OPS_VERIFY) {
                self.pub_key = key.get_pub_key()?;
            }
        } else if algs::KEY_DISTRIBUTION_ALGS.contains(&alg) || algs::ENCRYPT_ALGS.contains(&alg) {
            if KEY_OPS_SKEY.iter().any(|i| key.key_ops.contains(i)) {
                self.s_key = key.get_s_key()?;
            }
            if algs::ECDH_ALGS.contains(&alg) {
                if key.key_ops.len() == 0 {
                    self.pub_key = key.get_pub_key()?;
                }
            }
        }
        self.crv = key.crv;
        self.base_iv = key.base_iv.clone();
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
        Ok(cose_struct::gen_cipher(
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
        self.payload = cose_struct::gen_sig(
            &self.s_key,
            &self.header.alg.ok_or(JsValue::from("Missing alg"))?,
            &self.crv,
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
        Ok(cose_struct::verify_sig(
            &self.pub_key,
            &self.header.alg.ok_or(JsValue::from("Missing alg"))?,
            &self.crv,
            &external_aad,
            &self.context,
            &body_protected,
            &self.ph_bstr,
            &content,
            &self.payload,
        )?)
    }
    pub(crate) fn mac(
        &mut self,
        content: &Vec<u8>,
        external_aad: &Vec<u8>,
        body_protected: &Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        self.ph_bstr = self.header.get_protected_bstr(false)?;
        if !self.key_ops.contains(&keys::KEY_OPS_MAC) {
            return Err(JsValue::from("Key op not supported"));
        }
        Ok(cose_struct::gen_mac(
            &self.s_key,
            &self.header.alg.ok_or(JsValue::from("Missing algorithm"))?,
            &external_aad,
            &self.context,
            &body_protected,
            &content,
        )?)
    }

    pub fn add_signature(&mut self, signature: Vec<u8>) -> Result<(), JsValue> {
        if self.context != cose_struct::COUNTER_SIGNATURE {
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
        if self.context != cose_struct::COUNTER_SIGNATURE {
            return Err("Method only available for COUNTER_SIGNATURE context".into());
        }
        self.ph_bstr = self.header.get_protected_bstr(false)?;
        cose_struct::get_to_sign(
            &external_aad,
            cose_struct::COUNTER_SIGNATURE,
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
        let alg = self
            .header
            .alg
            .as_ref()
            .ok_or(JsValue::from("Missing algorithm"))?;
        if algs::A_KW.contains(alg) {
            if sender {
                self.payload = algs::aes_key_wrap(&self.s_key, *alg, &cek)?;
            } else {
                return Ok(algs::aes_key_unwrap(&self.s_key, *alg, &cek)?);
            }
            return Ok(cek.to_vec());
        } else if algs::RSA_OAEP.contains(alg) {
            if sender {
                self.payload = algs::rsa_oaep_enc(&self.s_key, size, &cek, alg)?;
            } else {
                return Ok(algs::rsa_oaep_dec(&self.s_key, size, &cek, alg)?);
            }
            return Ok(cek.to_vec());
        } else if algs::D_HA.contains(alg) {
            let mut kdf_context = cose_struct::gen_kdf(
                true_alg,
                &self.header.party_u_identity,
                &self.header.party_u_nonce,
                &self.header.party_u_other,
                &self.header.party_v_identity,
                &self.header.party_v_nonce,
                &self.header.party_v_other,
                size as u16 * 8,
                &self.ph_bstr,
                &self.header.pub_other,
                &self.header.priv_info,
            )?;
            return Ok(algs::hkdf(
                size,
                &self.s_key,
                self.header.salt.as_ref(),
                &mut kdf_context,
                self.header.alg.unwrap(),
            )?);
        } else if algs::D_HS.contains(alg) {
            let mut kdf_context = cose_struct::gen_kdf(
                true_alg,
                &self.header.party_u_identity,
                &self.header.party_u_nonce,
                &self.header.party_u_other,
                &self.header.party_v_identity,
                &self.header.party_v_nonce,
                &self.header.party_v_other,
                size as u16 * 8,
                &self.ph_bstr,
                &self.header.pub_other,
                &self.header.priv_info,
            )?;
            return Ok(algs::hkdf(
                size,
                &self.s_key,
                self.header.salt.as_ref(),
                &mut kdf_context,
                self.header.alg.unwrap(),
            )?);
        } else if algs::ECDH_H.contains(alg) || algs::ECDH_A.contains(alg) {
            let (receiver_key, sender_key, crv_rec, crv_send);
            if sender {
                if self.pub_key.len() == 0 {
                    return Err(JsValue::from("Missing key"));
                }
                receiver_key = self.pub_key.clone();
                sender_key = self.header.ecdh_key.get_s_key()?;
                crv_send = self.header.ecdh_key.crv.unwrap();
                crv_rec = self.crv.unwrap();
            } else {
                if self.s_key.len() == 0 {
                    return Err(JsValue::from("Missing key"));
                }
                receiver_key = self.header.ecdh_key.get_pub_key()?;
                crv_rec = self.crv.unwrap();
                sender_key = self.s_key.clone();
                crv_send = self.crv.unwrap();
            }
            let shared = algs::ecdh_derive_key(crv_rec, crv_send, &receiver_key, &sender_key)?;

            if algs::ECDH_H.contains(alg) {
                let mut kdf_context = cose_struct::gen_kdf(
                    true_alg,
                    &self.header.party_u_identity,
                    &self.header.party_u_nonce,
                    &self.header.party_u_other,
                    &self.header.party_v_identity,
                    &self.header.party_v_nonce,
                    &self.header.party_v_other,
                    size as u16 * 8,
                    &self.ph_bstr,
                    &self.header.pub_other,
                    &self.header.priv_info,
                )?;
                return Ok(algs::hkdf(
                    size,
                    &shared,
                    self.header.salt.as_ref(),
                    &mut kdf_context,
                    self.header.alg.unwrap(),
                )?);
            } else {
                let size_akw = algs::get_cek_size(&alg)?;

                let alg_akw;
                if [algs::ECDH_ES_A128KW, algs::ECDH_SS_A128KW].contains(alg) {
                    alg_akw = algs::A128KW;
                } else if [algs::ECDH_ES_A192KW, algs::ECDH_SS_A192KW].contains(alg) {
                    alg_akw = algs::A192KW;
                } else {
                    alg_akw = algs::A256KW;
                }

                let mut kdf_context = cose_struct::gen_kdf(
                    &alg_akw,
                    &self.header.party_u_identity,
                    &self.header.party_u_nonce,
                    &self.header.party_u_other,
                    &self.header.party_v_identity,
                    &self.header.party_v_nonce,
                    &self.header.party_v_other,
                    size_akw as u16 * 8,
                    &self.ph_bstr,
                    &self.header.pub_other,
                    &self.header.priv_info,
                )?;
                let kek = algs::hkdf(
                    size_akw,
                    &shared,
                    self.header.salt.as_ref(),
                    &mut kdf_context,
                    self.header.alg.unwrap(),
                )?;
                if sender {
                    self.payload = algs::aes_key_wrap(&kek, alg_akw, &cek)?;
                } else {
                    return Ok(algs::aes_key_unwrap(&kek, alg_akw, &cek)?);
                }
                return Ok(cek.to_vec());
            }
        } else {
            return Err(JsValue::from("Invalid algorithm"));
        }
    }

    pub(crate) fn decode(&mut self, d: &mut Decoder) -> Result<(), JsValue> {
        if self.ph_bstr.len() > 0 {
            self.header.decode_protected_bstr(self.ph_bstr.clone())?;
        }
        self.header
            .decode_unprotected(d, self.context == cose_struct::COUNTER_SIGNATURE)?;
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
