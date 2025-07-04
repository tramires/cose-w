use crate::agent::CoseAgent;
use crate::algs;
use crate::cbor::{Decoder, Encoder, CBOR_NULL};
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
    algs::SIGNING_ALGS_NAMES
        .iter()
        .zip(algs::SIGNING_ALGS.iter())
        .chain(
            algs::ENCRYPT_ALGS_NAMES
                .iter()
                .zip(algs::ENCRYPT_ALGS.iter()),
        )
        .chain(algs::MAC_ALGS_NAMES.iter().zip(algs::MAC_ALGS.iter()))
        .chain(
            algs::KEY_DISTRIBUTION_NAMES
                .iter()
                .zip(algs::KEY_DISTRIBUTION_ALGS.iter()),
        )
        .find(|(name, _)| **name == alg)
        .map(|(_, &val)| val)
        .ok_or_else(|| "Invalid Algorithm".into())
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
    pub(crate) pub_other: Option<Vec<u8>>,
    pub(crate) priv_info: Option<Vec<u8>>,
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
            pub_other: None,
            priv_info: None,
            static_kid: None,
            ecdh_key: keys::CoseKey::new(),
        }
    }
    #[wasm_bindgen(getter)]
    pub fn alg(&self) -> Option<i32> {
        self.alg.clone()
    }
    pub fn set_alg(&mut self, alg: i32, prot: bool, crit: bool) {
        self.reg_label(ALG, prot, crit);
        self.alg = Some(alg);
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
    pub fn set_content_type(&mut self, content_type: u32, prot: bool, crit: bool) {
        self.reg_label(CONTENT_TYPE, prot, crit);
        self.content_type = Some(ContentTypeTypes::Uint(content_type));
    }
    #[wasm_bindgen(getter)]
    pub fn kid(&self) -> Option<Vec<u8>> {
        self.kid.clone()
    }
    pub fn set_kid(&mut self, kid: Vec<u8>, prot: bool, crit: bool) {
        self.reg_label(KID, prot, crit);
        self.kid = Some(kid);
    }
    #[wasm_bindgen(getter)]
    pub fn iv(&self) -> Option<Vec<u8>> {
        self.iv.clone()
    }
    pub fn set_iv(&mut self, iv: Vec<u8>, prot: bool, crit: bool) {
        self.remove_label(PARTIAL_IV);
        self.partial_iv = None;
        self.reg_label(IV, prot, crit);
        self.iv = Some(iv);
    }
    #[wasm_bindgen(getter)]
    pub fn partial_iv(&self) -> Option<Vec<u8>> {
        self.partial_iv.clone()
    }
    pub fn set_partial_iv(&mut self, partial_iv: Vec<u8>, prot: bool, crit: bool) {
        self.remove_label(IV);
        self.iv = None;
        self.reg_label(PARTIAL_IV, prot, crit);
        self.partial_iv = Some(partial_iv);
    }
    #[wasm_bindgen(getter)]
    pub fn salt(&self) -> Option<Vec<u8>> {
        self.salt.clone()
    }
    pub fn set_salt(&mut self, salt: Vec<u8>, prot: bool, crit: bool) {
        self.reg_label(SALT, prot, crit);
        self.salt = Some(salt);
    }
    #[wasm_bindgen(getter)]
    pub fn party_u_identity(&self) -> Option<Vec<u8>> {
        self.party_u_identity.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn party_v_identity(&self) -> Option<Vec<u8>> {
        self.party_v_identity.clone()
    }
    pub fn set_party_identity(
        &mut self,
        identity: Vec<u8>,
        prot: bool,
        crit: bool,
        u: bool,
        include: bool,
    ) {
        if u {
            if include {
                self.reg_label(PARTY_U_IDENTITY, prot, crit);
            }
            self.party_u_identity = Some(identity);
        } else {
            if include {
                self.reg_label(PARTY_V_IDENTITY, prot, crit);
            }
            self.party_v_identity = Some(identity);
        }
    }
    #[wasm_bindgen(getter)]
    pub fn party_u_nonce(&self) -> Option<Vec<u8>> {
        self.party_u_nonce.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn party_v_nonce(&self) -> Option<Vec<u8>> {
        self.party_v_nonce.clone()
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
    #[wasm_bindgen(getter)]
    pub fn party_u_other(&self) -> Option<Vec<u8>> {
        self.party_u_other.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn party_v_other(&self) -> Option<Vec<u8>> {
        self.party_v_other.clone()
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
    #[wasm_bindgen(getter)]
    pub fn ecdh_key(&self) -> keys::CoseKey {
        self.ecdh_key.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_ecdh_key(&mut self, key: keys::CoseKey) {
        self.ecdh_key = key;
    }
    #[wasm_bindgen(getter)]
    pub fn static_kid(&self) -> Option<Vec<u8>> {
        self.static_kid.clone()
    }
    pub fn set_static_kid(&mut self, kid: Vec<u8>, key: keys::CoseKey, prot: bool, crit: bool) {
        self.remove_label(STATIC_KEY);
        self.remove_label(EPHEMERAL_KEY);
        self.reg_label(STATIC_KEY_ID, prot, crit);
        self.ecdh_key = key;
        self.static_kid = Some(kid);
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

    #[wasm_bindgen(getter)]
    pub fn pub_other(&self) -> Option<Vec<u8>> {
        self.pub_other.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_pub_other(&mut self, other: Option<Vec<u8>>) {
        self.pub_other = other;
    }
    #[wasm_bindgen(getter)]
    pub fn priv_info(&self) -> Option<Vec<u8>> {
        self.priv_info.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_priv_info(&mut self, info: Option<Vec<u8>>) {
        self.priv_info = info;
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
    pub fn crit(&self) -> Vec<i32> {
        self.crit.clone()
    }
    pub(crate) fn remove_label(&mut self, label: i32) {
        self.unprotected.retain(|&x| x != label);
        self.protected.retain(|&x| x != label);
        self.crit.retain(|&x| x != label);
    }
    fn reg_label(&mut self, label: i32, prot: bool, crit: bool) {
        self.remove_label(label);
        if prot {
            self.protected.push(label);
        } else {
            self.unprotected.push(label);
        }
        if crit && !self.crit.contains(&label) {
            self.crit.push(label);
        }
    }
    fn encode_label(
        &mut self,
        label: i32,
        encoder: &mut Encoder,
        protected: bool,
    ) -> Result<(), JsValue> {
        match label {
            ALG => {
                encoder.signed(self.alg.ok_or(JsValue::from("Missing alg"))?);
            }
            KID => {
                encoder.bytes(&self.kid.as_ref().ok_or(JsValue::from("Missing KID"))?);
            }
            IV => {
                encoder.bytes(&self.iv.as_ref().ok_or(JsValue::from("Missing IV"))?);
            }
            PARTIAL_IV => {
                encoder.bytes(
                    &self
                        .partial_iv
                        .as_ref()
                        .ok_or(JsValue::from("Missing Partial IV"))?,
                );
            }
            SALT => {
                encoder.bytes(&self.salt.as_ref().ok_or(JsValue::from("Missing salt"))?);
            }
            CONTENT_TYPE => {
                match &self
                    .content_type
                    .as_ref()
                    .ok_or(JsValue::from("Missing content-type"))?
                {
                    ContentTypeTypes::Uint(v) => encoder.unsigned(*v),
                    ContentTypeTypes::Tstr(v) => encoder.text(v),
                }
            }
            PARTY_U_IDENTITY => {
                encoder.bytes(
                    &self
                        .party_u_identity
                        .as_ref()
                        .ok_or(JsValue::from("Missing Party U Identity"))?,
                );
            }
            PARTY_U_NONCE => {
                encoder.bytes(
                    &self
                        .party_u_nonce
                        .as_ref()
                        .ok_or(JsValue::from("Missing Party U Nonce"))?,
                );
            }
            PARTY_U_OTHER => {
                encoder.bytes(
                    &self
                        .party_u_other
                        .as_ref()
                        .ok_or(JsValue::from("Missing Party U Other"))?,
                );
            }
            PARTY_V_IDENTITY => {
                encoder.bytes(
                    &self
                        .party_v_identity
                        .as_ref()
                        .ok_or(JsValue::from("Missing Party V Identity"))?,
                );
            }
            PARTY_V_NONCE => {
                encoder.bytes(
                    &self
                        .party_v_nonce
                        .as_ref()
                        .ok_or(JsValue::from("Missing Party V Nonce"))?,
                );
            }
            PARTY_V_OTHER => {
                encoder.bytes(
                    &self
                        .party_v_other
                        .as_ref()
                        .ok_or(JsValue::from("Missing Party V Other"))?,
                );
            }
            EPHEMERAL_KEY | STATIC_KEY => {
                let mut ecdh_key = self.ecdh_key.clone();
                ecdh_key.remove_label(keys::D);
                ecdh_key.d = None;
                if label == EPHEMERAL_KEY {
                    ecdh_key.remove_label(keys::KID)
                }
                ecdh_key.kid = None;
                ecdh_key.encode_key(encoder)?;
            }
            STATIC_KEY_ID => {
                encoder.bytes(
                    &self
                        .static_kid
                        .as_ref()
                        .ok_or(JsValue::from("Missing Static KID"))?,
                );
            }
            COUNTER_SIG if !protected => {
                if self.counters.len() > 1 {
                    encoder.array(self.counters.len());
                }
                for counter in &mut self.counters {
                    counter.encode(encoder)?;
                }
            }
            _ => {
                return Err(JsValue::from(
                    "Invalid label ".to_owned() + &label.to_string(),
                ));
            }
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
        match label {
            ALG => {
                self.alg = match decoder.signed() {
                    Ok(value) => Some(value),
                    Err(_) => match decoder.text() {
                        Ok(value) => Some(get_alg_id(value)?),
                        Err(_) => {
                            return Err(JsValue::from("Invalid COSE Structure"));
                        }
                    },
                };
            }
            CRIT if protected => {
                self.crit = Vec::new();
                for _ in 0..decoder.array()? {
                    self.crit.push(decoder.signed()?);
                }
            }
            CONTENT_TYPE => {
                self.content_type = match decoder.unsigned() {
                    Ok(value) => Some(ContentTypeTypes::Uint(value)),
                    Err(_) => match decoder.text() {
                        Ok(value) => Some(ContentTypeTypes::Tstr(value.to_string())),
                        Err(_) => {
                            return Err(JsValue::from("Invalid COSE Structure"));
                        }
                    },
                };
            }
            KID => {
                self.kid = Some(decoder.bytes()?.to_vec());
            }
            IV => {
                self.iv = Some(decoder.bytes()?);
            }
            SALT => {
                self.salt = Some(decoder.bytes()?);
            }
            PARTY_U_IDENTITY => {
                self.party_u_identity = Some(decoder.bytes()?);
            }
            PARTY_U_NONCE => {
                self.party_u_nonce = match decoder.bytes() {
                    Ok(value) => Some(value),
                    Err(err) => {
                        if err == CBOR_NULL {
                            None
                        } else {
                            return Err(JsValue::from("Invalid COSE Structure"));
                        }
                    }
                };
            }
            PARTY_U_OTHER => {
                self.party_u_other = Some(decoder.bytes()?);
            }
            PARTY_V_IDENTITY => {
                self.party_v_identity = Some(decoder.bytes()?);
            }
            PARTY_V_NONCE => {
                self.party_v_nonce = match decoder.bytes() {
                    Ok(value) => Some(value),
                    Err(err) => {
                        if err == CBOR_NULL {
                            None
                        } else {
                            return Err(JsValue::from("Invalid COSE Structure"));
                        }
                    }
                };
            }
            PARTY_V_OTHER => {
                self.party_v_other = Some(decoder.bytes()?);
            }
            PARTIAL_IV => {
                self.partial_iv = Some(decoder.bytes()?);
            }
            EPHEMERAL_KEY => {
                self.ecdh_key.decode_key(decoder)?;
            }
            STATIC_KEY => {
                self.ecdh_key.decode_key(decoder)?;
            }
            STATIC_KEY_ID => {
                self.static_kid = Some(decoder.bytes()?);
            }
            COUNTER_SIG if !is_counter_sig => {
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
            }
            _ => {
                return Err(JsValue::from(
                    "Invalid label ".to_owned() + &label.to_string(),
                ));
            }
        }
        Ok(())
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
}

#[cfg(test)]
mod test_vecs {
    use crate::headers::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_unique_header() {
        let mut header = CoseHeader::new();
        header.set_alg(algs::A128GCM, false, false);
        assert_eq!(vec![ALG], header.unprotected);
        assert!(header.protected.is_empty());
        header.set_alg(algs::A128GCM, true, false);
        assert_eq!(vec![ALG], header.protected);
        assert!(header.unprotected.is_empty());
    }

    #[wasm_bindgen_test]
    fn test_crit() {
        let mut header = CoseHeader::new();
        header.set_alg(algs::A128GCM, false, true);
        assert_eq!([ALG].to_vec(), header.crit);
        header.set_kid(vec![], false, true);
        assert_eq!([ALG, KID].to_vec(), header.crit);
        header.set_alg(algs::A128GCM, false, false);
        assert_eq!([KID].to_vec(), header.crit);
        header.set_kid(vec![], false, false);
        assert!(header.crit.is_empty());
    }

    #[wasm_bindgen_test]
    fn test_iv_and_partial() {
        let mut header = CoseHeader::new();
        header.set_iv(vec![], false, true);
        assert_eq!(vec![IV], header.unprotected);
        assert_eq!(vec![IV], header.crit);
        header.set_partial_iv(vec![], false, true);
        assert_eq!(vec![PARTIAL_IV], header.unprotected);
        assert_eq!(vec![PARTIAL_IV], header.crit);
    }

    #[wasm_bindgen_test]
    fn test_ecdh_key_unique() {
        let key = keys::CoseKey::new();
        let mut header = CoseHeader::new();

        header.set_static_kid(vec![], key.clone(), false, true);
        assert_eq!(vec![STATIC_KEY_ID], header.unprotected);
        assert_eq!(vec![STATIC_KEY_ID], header.crit);

        header.ephemeral_key(key.clone(), false, true);
        assert_eq!(vec![EPHEMERAL_KEY], header.unprotected);
        assert_eq!(vec![EPHEMERAL_KEY], header.crit);

        header.static_key(key, false, true);
        assert_eq!(vec![STATIC_KEY], header.unprotected);
        assert_eq!(vec![STATIC_KEY], header.crit);
    }

    #[wasm_bindgen_test]
    fn decode_duplicate_label() {
        let encoded = hex::decode("a3012601382e04423131").unwrap();
        let mut header = CoseHeader::new();
        assert_eq!(
            header.decode_protected_bstr(encoded),
            Err("Duplicate label 1".into())
        );
    }

    #[wasm_bindgen_test]
    fn decode_invalid_label() {
        let encoded = hex::decode("a30126190fa0382e04423131").unwrap();
        let mut header = CoseHeader::new();
        assert_eq!(
            header.decode_protected_bstr(encoded),
            Err("Invalid label 4000".into())
        );
    }
    #[wasm_bindgen_test]
    fn header_encode_decode() {
        let unprot_bytes = hex::decode("a205400301").unwrap();
        let prot_bytes = hex::decode("a2012604423131").unwrap();
        let kid = b"11".to_vec();
        let content_type = "1";

        let mut header = CoseHeader::new();
        header.set_alg(algs::ES256, true, false);
        header.set_kid(kid.clone(), true, false);
        header.set_iv(vec![], false, false);
        header.set_content_type(content_type.parse::<u32>().unwrap(), false, false);
        let mut encoder = Encoder::new();
        header.encode_unprotected(&mut encoder).unwrap();
        assert_eq!(unprot_bytes, encoder.encoded());

        assert_eq!(prot_bytes, header.get_protected_bstr(true).unwrap());

        header = CoseHeader::new();
        header.decode_protected_bstr(prot_bytes).unwrap();

        assert_eq!(header.alg(), Some(algs::ES256));
        assert_eq!(header.kid(), Some(kid.clone()));
        assert_eq!(header.iv(), None);
        assert_eq!(header.content_type(), None);

        let mut decoder = Decoder::new(unprot_bytes);
        header.decode_unprotected(&mut decoder, false).unwrap();

        assert_eq!(header.alg(), Some(algs::ES256));
        assert_eq!(header.kid(), Some(kid));
        assert_eq!(header.iv(), Some(vec![]));
        assert_eq!(header.content_type(), Some(content_type.to_string()));
    }
}
