use crate::agent::CoseAgent;
use crate::algs;
use crate::cbor::{Decoder, Encoder};
use crate::keys;
use wasm_bindgen::prelude::*;

pub(crate) const SALT: i32 = -20;
pub(crate) const ALG: i32 = 1;
pub(crate) const CRIT: i32 = 2;
pub(crate) const CONTENT_TYPE: i32 = 3;
pub(crate) const KID: i32 = 4;
pub(crate) const IV: i32 = 5;
pub(crate) const PARTIAL_IV: i32 = 6;
pub(crate) const COUNTER_SIG: i32 = 7;

pub(crate) const PARTY_U_IDENTITY: i32 = -21;
pub(crate) const PARTY_U_NONCE: i32 = -22;
pub(crate) const PARTY_U_OTHER: i32 = -23;
pub(crate) const PARTY_V_IDENTITY: i32 = -24;
pub(crate) const PARTY_V_NONCE: i32 = -25;
pub(crate) const PARTY_V_OTHER: i32 = -26;

pub(crate) const EPHEMERAL_KEY: i32 = -1;
pub(crate) const STATIC_KEY: i32 = -2;
pub(crate) const STATIC_KEY_ID: i32 = -3;

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

#[derive(Clone, PartialEq)]
pub(crate) enum ContentTypeTypes {
    Uint(u32),
    Tstr(String),
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct CoseHeader {
    pub(crate) protected: Vec<i32>,
    pub(crate) unprotected: Vec<i32>,
    pub(crate) alg: Option<i32>,
    pub(crate) crit: Vec<i32>,
    pub(crate) content_type: Option<ContentTypeTypes>,
    pub(crate) kid: Option<Vec<u8>>,
    pub(crate) iv: Option<Vec<u8>>,
    pub(crate) partial_iv: Option<Vec<u8>>,
    pub(crate) salt: Option<Vec<u8>>,
    pub(crate) counters: Vec<CoseAgent>,
    pub(crate) party_u_identity: Option<Vec<u8>>,
    pub(crate) party_u_nonce: Option<Vec<u8>>,
    pub(crate) party_u_other: Option<Vec<u8>>,
    pub(crate) party_v_identity: Option<Vec<u8>>,
    pub(crate) party_v_nonce: Option<Vec<u8>>,
    pub(crate) party_v_other: Option<Vec<u8>>,
    pub(crate) ecdh_key: keys::CoseKey,
    pub(crate) static_kid: Option<Vec<u8>>,
    pub(crate) labels_found: Vec<i32>,
}

#[wasm_bindgen]
impl CoseHeader {
    #[wasm_bindgen(constructor)]
    pub fn new() -> CoseHeader {
        CoseHeader {
            labels_found: Vec::new(),
            unprotected: Vec::new(),
            protected: Vec::new(),
            counters: Vec::new(),
            crit: Vec::new(),
            content_type: None,
            partial_iv: None,
            salt: None,
            alg: None,
            kid: None,
            iv: None,
            party_u_identity: None,
            party_v_identity: None,
            party_u_nonce: None,
            party_v_nonce: None,
            party_u_other: None,
            party_v_other: None,
            static_kid: None,
            ecdh_key: keys::CoseKey::new(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn protected(&self) -> Vec<i32> {
        self.protected.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn unprotected(&self) -> Vec<i32> {
        self.unprotected.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn alg(&self) -> Option<i32> {
        self.alg.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn crit(&self) -> Vec<i32> {
        self.crit.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn content_type(&self) -> Option<String> {
        if self.content_type == None {
            return None;
        }
        match self.content_type.as_ref().unwrap() {
            ContentTypeTypes::Uint(v) => Some(v.to_string()),
            ContentTypeTypes::Tstr(v) => Some(v.to_string()),
        }
    }
    #[wasm_bindgen(getter)]
    pub fn kid(&self) -> Option<Vec<u8>> {
        self.kid.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn iv(&self) -> Option<Vec<u8>> {
        self.iv.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn partial_iv(&self) -> Option<Vec<u8>> {
        self.partial_iv.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn salt(&self) -> Option<Vec<u8>> {
        self.salt.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn party_u_identity(&self) -> Option<Vec<u8>> {
        self.party_u_identity.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn party_u_nonce(&self) -> Option<Vec<u8>> {
        self.party_u_nonce.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn party_u_other(&self) -> Option<Vec<u8>> {
        self.party_u_other.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn party_v_identity(&self) -> Option<Vec<u8>> {
        self.party_v_identity.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn party_v_nonce(&self) -> Option<Vec<u8>> {
        self.party_v_nonce.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn party_v_other(&self) -> Option<Vec<u8>> {
        self.party_v_other.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn ecdh_key(&self) -> keys::CoseKey {
        self.ecdh_key.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn static_kid(&self) -> Option<Vec<u8>> {
        self.static_kid.clone()
    }

    pub(crate) fn remove_label(&mut self, label: i32) {
        self.unprotected.retain(|&x| x != label);
        self.protected.retain(|&x| x != label);
    }

    fn reg_label(&mut self, label: i32, prot: bool, crit: bool) {
        self.remove_label(label);
        if prot {
            self.protected.push(label);
        } else {
            self.unprotected.push(label);
        }
        if crit && !self.crit.contains(&label) {
            self.crit.push(ALG);
        }
    }

    pub fn set_alg(&mut self, alg: i32, prot: bool, crit: bool) {
        self.reg_label(ALG, prot, crit);
        self.alg = Some(alg);
    }

    pub fn set_kid(&mut self, kid: Vec<u8>, prot: bool, crit: bool) {
        self.reg_label(KID, prot, crit);
        self.kid = Some(kid);
    }

    pub fn set_iv(&mut self, iv: Vec<u8>, prot: bool, crit: bool) {
        self.remove_label(PARTIAL_IV);
        self.partial_iv = None;
        self.reg_label(IV, prot, crit);
        self.iv = Some(iv);
    }

    pub fn set_partial_iv(&mut self, partial_iv: Vec<u8>, prot: bool, crit: bool) {
        self.remove_label(IV);
        self.iv = None;
        self.reg_label(PARTIAL_IV, prot, crit);
        self.partial_iv = Some(partial_iv);
    }

    pub fn set_salt(&mut self, salt: Vec<u8>, prot: bool, crit: bool) {
        self.reg_label(SALT, prot, crit);
        self.salt = Some(salt);
    }

    pub fn set_content_type(&mut self, content_type: u32, prot: bool, crit: bool) {
        self.reg_label(CONTENT_TYPE, prot, crit);
        self.content_type = Some(ContentTypeTypes::Uint(content_type));
    }

    pub fn set_party_identity(&mut self, identity: Vec<u8>, prot: bool, crit: bool, u: bool) {
        if u {
            self.reg_label(PARTY_U_IDENTITY, prot, crit);
            self.party_u_identity = Some(identity);
        } else {
            self.reg_label(PARTY_V_IDENTITY, prot, crit);
            self.party_v_identity = Some(identity);
        }
    }

    pub fn set_party_nonce(&mut self, nonce: Vec<u8>, prot: bool, crit: bool, u: bool) {
        if u {
            self.reg_label(PARTY_U_NONCE, prot, crit);
            self.party_u_nonce = Some(nonce);
        } else {
            self.reg_label(PARTY_V_NONCE, prot, crit);
            self.party_v_nonce = Some(nonce);
        }
    }

    pub fn set_party_other(&mut self, other: Vec<u8>, prot: bool, crit: bool, u: bool) {
        if u {
            self.reg_label(PARTY_U_OTHER, prot, crit);
            self.party_u_other = Some(other);
        } else {
            self.reg_label(PARTY_V_OTHER, prot, crit);
            self.party_v_other = Some(other);
        }
    }

    pub fn ephemeral_key(&mut self, key: keys::CoseKey, prot: bool, crit: bool) {
        self.remove_label(STATIC_KEY_ID);
        self.remove_label(STATIC_KEY);
        self.static_kid = None;
        self.reg_label(EPHEMERAL_KEY, prot, crit);
        self.ecdh_key = key;
    }

    pub fn static_key(&mut self, key: keys::CoseKey, prot: bool, crit: bool) {
        self.remove_label(STATIC_KEY_ID);
        self.remove_label(EPHEMERAL_KEY);
        self.static_kid = None;
        self.reg_label(STATIC_KEY, prot, crit);
        self.ecdh_key = key;
    }

    pub fn set_static_kid(&mut self, kid: Vec<u8>, key: keys::CoseKey, prot: bool, crit: bool) {
        self.remove_label(STATIC_KEY);
        self.remove_label(EPHEMERAL_KEY);
        self.reg_label(STATIC_KEY_ID, prot, crit);
        self.ecdh_key = key;
        self.static_kid = Some(kid);
    }

    pub fn set_ecdh_key(&mut self, key: keys::CoseKey) {
        self.ecdh_key = key;
    }

    pub(crate) fn encode_unprotected(&mut self, encoder: &mut Encoder) -> Result<(), JsValue> {
        encoder.object(self.unprotected.len());
        for i in 0..self.unprotected.len() {
            if !self.labels_found.contains(&self.unprotected[i]) {
                self.labels_found.push(self.unprotected[i]);
            } else {
                return Err(JsValue::from(
                    "Duplicate label ".to_owned() + &self.unprotected[i].to_string(),
                ));
            };
            encoder.signed(self.unprotected[i]);
            self.encode_label(self.unprotected[i], encoder, false)?;
        }
        Ok(())
    }

    pub(crate) fn get_protected_bstr(&mut self, verify_label: bool) -> Result<Vec<u8>, JsValue> {
        let mut ph_bstr = Vec::new();
        let mut encoder = Encoder::new();
        let prot_len = self.protected.len();
        let crit_len = self.crit.len();
        if crit_len > 0 || prot_len > 0 {
            if crit_len > 0 {
                encoder.object(prot_len + 1);
                encoder.signed(CRIT);
                encoder.array(crit_len);
                for i in &self.crit {
                    encoder.signed(*i);
                }
            } else {
                encoder.object(prot_len);
            }
            for i in 0..self.protected.len() {
                if verify_label {
                    if !self.labels_found.contains(&self.protected[i]) {
                        self.labels_found.push(self.protected[i]);
                    } else {
                        return Err(JsValue::from(
                            "Duplicate label ".to_owned() + &self.protected[i].to_string(),
                        ));
                    };
                }
                encoder.signed(self.protected[i]);
                self.encode_label(self.protected[i], &mut encoder, true)?;
            }
            ph_bstr = encoder.encoded();
        }
        Ok(ph_bstr)
    }

    pub(crate) fn decode_unprotected(
        &mut self,
        decoder: &mut Decoder,
        is_counter_sig: bool,
    ) -> Result<(), JsValue> {
        let unprot_len = decoder.object()?;
        self.unprotected = Vec::new();
        for _ in 0..unprot_len {
            let label = decoder.signed()?;
            if !self.labels_found.contains(&label) {
                self.labels_found.push(label);
            } else {
                return Err(JsValue::from(
                    "Duplicate label ".to_owned() + &label.to_string(),
                ));
            }
            self.decode_label(label, decoder, false, is_counter_sig)?;
        }
        Ok(())
    }

    pub(crate) fn decode_protected_bstr(&mut self, ph_bstr: Vec<u8>) -> Result<(), JsValue> {
        let mut decoder = Decoder::new(ph_bstr.clone());
        let prot_len = decoder.object()?;
        self.protected = Vec::new();
        for _ in 0..prot_len {
            let label = decoder.signed()?;
            if !self.labels_found.contains(&label) {
                self.labels_found.push(label);
            } else {
                return Err(JsValue::from(
                    "Duplicate label ".to_owned() + &label.to_string(),
                ));
            };
            self.decode_label(label, &mut decoder, true, false)?;
        }
        Ok(())
    }

    fn encode_label(
        &mut self,
        label: i32,
        encoder: &mut Encoder,
        protected: bool,
    ) -> Result<(), JsValue> {
        if label == ALG {
            encoder.signed(self.alg.ok_or(JsValue::from("Missing alg"))?);
        } else if label == KID {
            encoder.bytes(&self.kid.as_ref().ok_or(JsValue::from("Missing KID"))?);
        } else if label == IV {
            encoder.bytes(&self.iv.as_ref().ok_or(JsValue::from("Missing IV"))?);
        } else if label == PARTIAL_IV {
            encoder.bytes(
                &self
                    .partial_iv
                    .as_ref()
                    .ok_or(JsValue::from("Missing Partial IV"))?,
            );
        } else if label == SALT {
            encoder.bytes(&self.salt.as_ref().ok_or(JsValue::from("Missing salt"))?);
        } else if label == CONTENT_TYPE {
            match &self
                .content_type
                .as_ref()
                .ok_or(JsValue::from("Missing content-type"))?
            {
                ContentTypeTypes::Uint(v) => encoder.unsigned(*v),
                ContentTypeTypes::Tstr(v) => encoder.text(v),
            }
        } else if label == PARTY_U_IDENTITY {
            encoder.bytes(
                &self
                    .party_u_identity
                    .as_ref()
                    .ok_or(JsValue::from("Missing Party U Identity"))?,
            );
        } else if label == PARTY_U_NONCE {
            encoder.bytes(
                &self
                    .party_u_nonce
                    .as_ref()
                    .ok_or(JsValue::from("Missing Party U Nonce"))?,
            );
        } else if label == PARTY_U_OTHER {
            encoder.bytes(
                &self
                    .party_u_other
                    .as_ref()
                    .ok_or(JsValue::from("Missing Party U Other"))?,
            );
        } else if label == PARTY_V_IDENTITY {
            encoder.bytes(
                &self
                    .party_v_identity
                    .as_ref()
                    .ok_or(JsValue::from("Missing Party V Identity"))?,
            );
        } else if label == PARTY_V_NONCE {
            encoder.bytes(
                &self
                    .party_v_nonce
                    .as_ref()
                    .ok_or(JsValue::from("Missing Party V Nonce"))?,
            );
        } else if label == PARTY_V_OTHER {
            encoder.bytes(
                &self
                    .party_v_other
                    .as_ref()
                    .ok_or(JsValue::from("Missing Party V Other"))?,
            );
        } else if label == EPHEMERAL_KEY || label == STATIC_KEY {
            let mut ecdh_key = self.ecdh_key.clone();
            ecdh_key.remove_label(keys::D);
            ecdh_key.d = None;
            ecdh_key.encode_key(encoder)?;
        } else if label == STATIC_KEY_ID {
            encoder.bytes(
                &self
                    .static_kid
                    .as_ref()
                    .ok_or(JsValue::from("Missing Static KID"))?,
            );
        } else if label == COUNTER_SIG && !protected {
            if self.counters.len() > 1 {
                encoder.array(self.counters.len());
            }
            for counter in &mut self.counters {
                counter.encode(encoder)?;
            }
        } else {
            return Err(JsValue::from(
                "Invalid label ".to_owned() + &label.to_string(),
            ));
        }
        Ok(())
    }

    fn decode_label(
        &mut self,
        label: i32,
        decoder: &mut Decoder,
        protected: bool,
        is_counter_sig: bool,
    ) -> Result<(), JsValue> {
        if protected {
            self.protected.push(label);
        } else {
            self.unprotected.push(label);
        }
        if label == ALG {
            self.alg = match decoder.signed() {
                Ok(value) => Some(value),
                Err(_) => match decoder.text() {
                    Ok(value) => Some(get_alg_id(value)?),
                    Err(_) => {
                        return Err(JsValue::from("Invalid COSE Structure"));
                    }
                },
            };
        } else if label == CRIT && protected {
            self.crit = Vec::new();
            for _ in 0..decoder.array()? {
                self.crit.push(decoder.signed()?);
            }
        } else if label == CONTENT_TYPE {
            self.content_type = match decoder.unsigned() {
                Ok(value) => Some(ContentTypeTypes::Uint(value)),
                Err(_) => match decoder.text() {
                    Ok(value) => Some(ContentTypeTypes::Tstr(value.to_string())),
                    Err(_) => {
                        return Err(JsValue::from("Invalid COSE Structure"));
                    }
                },
            };
        } else if label == KID {
            self.kid = Some(decoder.bytes()?.to_vec());
        } else if label == IV {
            self.iv = Some(decoder.bytes()?);
        } else if label == SALT {
            self.salt = Some(decoder.bytes()?);
        } else if label == PARTY_U_IDENTITY {
            self.party_u_identity = Some(decoder.bytes()?);
        } else if label == PARTY_U_NONCE {
            self.party_u_nonce = match decoder.bytes() {
                Ok(value) => Some(value),
                Err(err) => {
                    if err == 246 {
                        None
                    } else {
                        return Err(JsValue::from("Invalid COSE Structure"));
                    }
                }
            };
        } else if label == PARTY_U_OTHER {
            self.party_u_other = Some(decoder.bytes()?);
        } else if label == PARTY_V_IDENTITY {
            self.party_v_identity = Some(decoder.bytes()?);
        } else if label == PARTY_V_NONCE {
            self.party_v_nonce = match decoder.bytes() {
                Ok(value) => Some(value),
                Err(err) => {
                    if err == 246 {
                        None
                    } else {
                        return Err(JsValue::from("Invalid COSE Structure"));
                    }
                }
            };
        } else if label == PARTY_V_OTHER {
            self.party_v_other = Some(decoder.bytes()?);
        } else if label == PARTIAL_IV {
            self.partial_iv = Some(decoder.bytes()?);
        } else if label == EPHEMERAL_KEY {
            self.ecdh_key.decode_key(decoder)?;
        } else if label == STATIC_KEY {
            self.ecdh_key.decode_key(decoder)?;
        } else if label == STATIC_KEY_ID {
            self.static_kid = Some(decoder.bytes()?);
        } else if label == COUNTER_SIG && !is_counter_sig {
            let mut counter = CoseAgent::new_counter_sig();
            let n = decoder.array()?;
            let mut n1 = 0;
            match decoder.bytes() {
                Ok(value) => {
                    counter.ph_bstr = value;
                }
                Err(_) => match decoder.array() {
                    Ok(value) => {
                        n1 = value;
                    }
                    Err(_) => {
                        return Err(JsValue::from("Invalid COSE Structure"));
                    }
                },
            };
            if n1 == 0 && n == 3 {
                counter.decode(decoder)?;
                self.counters.push(counter);
            } else {
                counter.ph_bstr = decoder.bytes()?;
                counter.decode(decoder)?;
                self.counters.push(counter);
                for _ in 1..n {
                    counter = CoseAgent::new_counter_sig();
                    decoder.array()?;
                    counter.ph_bstr = decoder.bytes()?;
                    counter.decode(decoder)?;
                    self.counters.push(counter);
                }
            }
        } else {
            return Err(JsValue::from(
                "Invalid label ".to_owned() + &label.to_string(),
            ));
        }
        Ok(())
    }
}
