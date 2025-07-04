use crate::algs;
use crate::cbor::{Decoder, Encoder};
use crate::cose_struct;
use crate::headers;
use crate::keys;
use wasm_bindgen::prelude::*;

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

#[wasm_bindgen]
impl CoseAgent {
    #[wasm_bindgen(constructor)]
    pub fn new() -> CoseAgent {
        CoseAgent {
            header: headers::CoseHeader::new(),
            payload: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            s_key: Vec::new(),
            context: "".to_string(),
            crv: None,
            key_ops: Vec::new(),
            base_iv: None,
            enc: false,
        }
    }
    pub fn new_counter_sig() -> CoseAgent {
        CoseAgent {
            header: headers::CoseHeader::new(),
            payload: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            s_key: Vec::new(),
            context: cose_struct::COUNTER_SIGNATURE.to_string(),
            crv: None,
            key_ops: Vec::new(),
            base_iv: None,
            enc: false,
        }
    }
    #[wasm_bindgen(getter)]
    pub fn header(&self) -> headers::CoseHeader {
        self.header.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_header(&mut self, header: headers::CoseHeader) {
        self.header = header;
    }
    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }
    pub fn ephemeral_key(&mut self, key: keys::CoseKey, prot: bool, crit: bool) {
        self.header.ephemeral_key(key, prot, crit);
    }
    pub fn static_key(&mut self, key: keys::CoseKey, prot: bool, crit: bool) {
        self.header.static_key(key, prot, crit);
    }
    pub fn static_kid(&mut self, kid: Vec<u8>, key: keys::CoseKey, prot: bool, crit: bool) {
        self.header.set_static_kid(kid, key, prot, crit);
    }
    pub(crate) fn enc(
        &mut self,
        content: &Vec<u8>,
        external_aad: &Vec<u8>,
        body_protected: &Vec<u8>,
        alg: &i32,
        iv: &Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        if !self.key_ops.is_empty() && !self.key_ops.contains(&keys::KEY_OPS_ENCRYPT) {
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
        if !self.key_ops.is_empty() && !self.key_ops.contains(&keys::KEY_OPS_SIGN) {
            return Err(JsValue::from("Missing Key key_ops_sign"));
        }
        self.ph_bstr = self.header.get_protected_bstr(false)?;
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
        if !self.key_ops.is_empty() && !self.key_ops.contains(&keys::KEY_OPS_VERIFY) {
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
    pub(crate) fn derive_key(
        &mut self,
        cek: &Vec<u8>,
        size: usize,
        sender: bool,
        true_alg: &i32,
    ) -> Result<Vec<u8>, JsValue> {
        if self.ph_bstr.is_empty() {
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
                self.payload = algs::rsa_oaep_enc(&self.pub_key, &cek, alg)?;
            } else {
                return Ok(algs::rsa_oaep_dec(&self.s_key, size, &cek, alg)?);
            }
            return Ok(cek.to_vec());
        } else if algs::D_HA.contains(alg) || algs::D_HS.contains(alg) {
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
                if self.pub_key.is_empty() {
                    return Err(JsValue::from("Missing key"));
                }
                receiver_key = self.pub_key.clone();
                sender_key = self.header.ecdh_key.get_s_key()?;
                crv_send = self.header.ecdh_key.crv.unwrap();
                crv_rec = self.crv.unwrap();
            } else {
                if self.s_key.is_empty() {
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
    pub(crate) fn decode(&mut self, d: &mut Decoder) -> Result<(), JsValue> {
        if !self.ph_bstr.is_empty() {
            self.header.decode_protected_bstr(self.ph_bstr.clone())?;
        }
        self.header
            .decode_unprotected(d, self.context == cose_struct::COUNTER_SIGNATURE)?;
        self.payload = d.bytes()?;
        Ok(())
    }
    pub(crate) fn encode(&mut self, e: &mut Encoder) -> Result<(), JsValue> {
        e.array(3);
        e.bytes(&self.ph_bstr);
        self.header.encode_unprotected(e)?;
        e.bytes(&self.payload);
        Ok(())
    }
    pub fn key(&mut self, key: &keys::CoseKey) -> Result<(), JsValue> {
        let alg = self.header.alg.ok_or(JsValue::from("Missing algorithm"))?;
        key.verify_kty()?;
        if algs::ECDH_ALGS.contains(&alg) {
            if !keys::ECDH_KTY.contains(key.kty.as_ref().ok_or(JsValue::from("Missing KTY"))?) {
                return Err(JsValue::from("Invalid KTY"));
            }
            if key.alg.is_some() && key.alg.unwrap() != alg {
                return Err(JsValue::from("Algorithms dont match"));
            }
        } else if (alg != algs::DIRECT
            && !algs::A_KW.contains(&alg)
            && !algs::RSA_OAEP.contains(&alg))
            && key.alg.is_some()
            && key.alg.unwrap() != alg
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
            if key.key_ops.is_empty() {
                self.s_key = match key.get_s_key() {
                    Ok(v) => v,
                    Err(_) => Vec::new(),
                };
                self.pub_key = match key.get_pub_key() {
                    Ok(v) => v,
                    Err(_) => Vec::new(),
                };
            }
        } else if algs::KEY_DISTRIBUTION_ALGS.contains(&alg) || algs::ENCRYPT_ALGS.contains(&alg) {
            if KEY_OPS_SKEY.iter().any(|i| key.key_ops.contains(i)) {
                self.s_key = key.get_s_key()?;
            }
            if key.key_ops.is_empty() {
                self.s_key = match key.get_s_key() {
                    Ok(v) => v,
                    Err(_) => Vec::new(),
                };
            }
            if algs::ECDH_ALGS.contains(&alg) || algs::OAEP_ALGS.contains(&alg) {
                if key.key_ops.is_empty() {
                    self.pub_key = key.get_pub_key()?;
                }
            }
        }
        self.crv = key.crv;
        self.base_iv = key.base_iv.clone();
        self.key_ops = key.key_ops.clone();
        Ok(())
    }
    pub fn add_signature(&mut self, signature: Vec<u8>) -> Result<(), JsValue> {
        if self.context != cose_struct::COUNTER_SIGNATURE {
            return Err("Method only available for COUNTER_SIGNATURE context".into());
        }
        self.payload = signature;
        Ok(())
    }
}

#[cfg(test)]
mod test_vecs {
    use crate::agent;
    use crate::algs;
    use crate::headers;
    use crate::keys;
    use crate::message::CoseMessage;
    use wasm_bindgen_test::*;

    pub fn get_test_vec(id: &str) -> Vec<u8> {
        let test_vecs = include_str!("../test_params/test_vecs.csv");
        let mut msg = vec![];
        for line in test_vecs.lines().skip(1) {
            let kp: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
            if kp[0] == id {
                msg = hex::decode(kp[1]).unwrap();
            }
        }
        msg
    }

    pub fn get_key(kid: Vec<u8>, public: bool) -> keys::CoseKey {
        let key_set;
        if public {
            key_set = include_str!("../test_params/pub_key_set");
        } else {
            key_set = include_str!("../test_params/priv_key_set");
        }
        let mut cose_ks = keys::CoseKeySet::new();
        cose_ks.set_bytes(hex::decode(key_set.trim()).unwrap());
        cose_ks.decode().unwrap();
        cose_ks.get_key(kid).unwrap()
    }

    #[wasm_bindgen_test]
    fn c13_external_counter_sig() {
        let kid = b"11".to_vec();
        let mut verify = CoseMessage::new_sign();
        verify.set_bytes(get_test_vec("C13"));

        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(kid.clone()).unwrap()[0];
        let key = get_key(kid, true);
        verify.set_agent_key(i, &key).unwrap();

        verify.decode(None, Some(i)).unwrap();

        let to_verify = verify.get_to_verify(None, 0, None).unwrap();
        algs::verify(
            algs::ES256,
            Some(keys::P_256),
            &key.get_pub_key().unwrap(),
            &to_verify,
            &verify.header.counters[0].payload,
        )
        .unwrap();
    }

    #[wasm_bindgen_test]
    fn prod_c13_external_counter_sig() {
        let kid = b"11".to_vec();
        let payload = b"This is the content.".to_vec();
        let mut sign = CoseMessage::new_sign();
        sign.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_kid(kid.clone(), false, false);
        header.set_alg(algs::ES256, true, false);

        let key = get_key(kid.clone(), false);

        let mut agent = agent::CoseAgent::new();
        agent.set_header(header);
        agent.key(&key).unwrap();

        sign.add_agent(&mut agent).unwrap();
        sign.secure_content(None).unwrap();

        let mut counter = agent::CoseAgent::new_counter_sig();

        let mut header = headers::CoseHeader::new();
        header.set_kid(kid, false, false);
        header.set_alg(algs::ES256, true, false);

        counter.set_header(header);

        let to_sign = sign.get_to_sign(None, &mut counter, None).unwrap();

        let payload = algs::sign(
            algs::ES256,
            Some(keys::P_256),
            &key.get_s_key().unwrap(),
            &to_sign,
        )
        .unwrap();

        counter.add_signature(payload).unwrap();

        sign.add_counter_sig(counter, None).unwrap();

        let bytes = sign.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C13"));
    }
}
