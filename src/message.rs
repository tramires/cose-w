use crate::agent::CoseAgent;
use crate::algs;
use crate::cbor::{Decoder, Encoder};
use crate::cose_struct;
use crate::headers::{CoseHeader, COUNTER_SIG};
use crate::keys;
use wasm_bindgen::prelude::*;

const SIG: usize = 0;
const MAC: usize = 1;
const ENC: usize = 2;

const MISS_ERR: [&str; 3] = ["signature", "tag", "ciphertext"];
const CONTEXTS: [&str; 3] = [
    cose_struct::SIGNATURE,
    cose_struct::MAC_RECIPIENT,
    cose_struct::ENCRYPT_RECIPIENT,
];
const KO: [[i32; 2]; 3] = [
    [keys::KEY_OPS_SIGN, keys::KEY_OPS_VERIFY],
    [keys::KEY_OPS_MAC, keys::KEY_OPS_MAC_VERIFY],
    [keys::KEY_OPS_ENCRYPT, keys::KEY_OPS_DECRYPT],
];

// COSE tags
pub const ENC0_TAG: u32 = 16;
pub const MAC0_TAG: u32 = 17;
pub const SIG1_TAG: u32 = 18;
pub const ENC_TAG: u32 = 96;
pub const MAC_TAG: u32 = 97;
pub const SIG_TAG: u32 = 98;

// COSE types in string
pub const ENC0_TYPE: &str = "cose-encrypt0";
pub const MAC0_TYPE: &str = "cose-mac0";
pub const SIG1_TYPE: &str = "cose-sign1";
pub const ENC_TYPE: &str = "cose-encrypt";
pub const MAC_TYPE: &str = "cose-mac";
pub const SIG_TYPE: &str = "cose-sign";

const SIZES: [[usize; 2]; 3] = [[4, 4], [4, 5], [3, 4]];
const TAGS: [[u32; 2]; 3] = [
    [SIG1_TAG, SIG_TAG],
    [MAC0_TAG, MAC_TAG],
    [ENC0_TAG, ENC_TAG],
];

#[wasm_bindgen]
pub struct CoseMessage {
    pub(crate) header: CoseHeader,
    pub(crate) payload: Vec<u8>,
    secured: Vec<u8>,
    pub(crate) bytes: Vec<u8>,
    ph_bstr: Vec<u8>,
    pub_key: Vec<u8>,
    priv_key: Vec<u8>,
    key_encode: bool,
    key_decode: bool,
    crv: Option<i32>,
    pub(crate) agents: Vec<CoseAgent>,
    context: usize,
}

#[wasm_bindgen]
impl CoseMessage {
    pub fn new_sign() -> CoseMessage {
        CoseMessage {
            bytes: Vec::new(),
            header: CoseHeader::new(),
            payload: Vec::new(),
            secured: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            priv_key: Vec::new(),
            key_encode: false,
            key_decode: false,
            agents: Vec::new(),
            crv: None,
            context: SIG,
        }
    }
    pub fn new_encrypt() -> CoseMessage {
        CoseMessage {
            bytes: Vec::new(),
            header: CoseHeader::new(),
            payload: Vec::new(),
            secured: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            priv_key: Vec::new(),
            key_encode: false,
            key_decode: false,
            agents: Vec::new(),
            crv: None,
            context: ENC,
        }
    }
    pub fn new_mac() -> CoseMessage {
        CoseMessage {
            bytes: Vec::new(),
            header: CoseHeader::new(),
            payload: Vec::new(),
            secured: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            priv_key: Vec::new(),
            key_encode: false,
            key_decode: false,
            agents: Vec::new(),
            crv: None,
            context: MAC,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn header(&self) -> CoseHeader {
        self.header.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn counters_len(&self) -> usize {
        self.header.counters.len()
    }

    pub fn counter_header(&self, i: usize) -> CoseHeader {
        self.header.counters[i].header.clone()
    }

    pub fn counter(&mut self, kid: Vec<u8>) -> Result<Vec<usize>, JsValue> {
        let mut counters: Vec<usize> = Vec::new();
        for i in 0..self.header.counters.len() {
            if self.header.counters[i]
                .header
                .kid
                .as_ref()
                .ok_or(JsValue::from("Missing KID"))?
                == &kid
            {
                counters.push(i);
            }
        }
        Ok(counters)
    }

    pub fn agent_header(&self, i: usize) -> CoseHeader {
        self.agents[i].header.clone()
    }

    pub fn add_agent_key(&mut self, index: usize, cose_key: &keys::CoseKey) -> Result<(), JsValue> {
        if index < self.agents.len() {
            self.agents[index].key(cose_key)?;
            Ok(())
        } else {
            Err(JsValue::from("Invalid index provided"))
        }
    }

    pub fn add_counter_key(&mut self, i: usize, key: &keys::CoseKey) -> Result<(), JsValue> {
        self.header.counters[i].key(key)?;
        Ok(())
    }

    pub fn set_header(&mut self, header: CoseHeader) {
        self.header = header;
    }

    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    pub fn set_bytes(&mut self, bytes: Vec<u8>) {
        self.bytes = bytes;
    }

    pub fn add_agent(&mut self, agent: &mut CoseAgent) -> Result<(), JsValue> {
        agent.context = CONTEXTS[self.context].to_string();
        if self.context == SIG {
            if !algs::SIGNING_ALGS.contains(&agent.header.alg.ok_or(JsValue::from("Missing alg"))?)
            {
                return Err(JsValue::from("Invalid algorithm for SIGNATURE context"));
            }
            if !agent.key_ops.contains(&keys::KEY_OPS_SIGN) {
                return Err(JsValue::from("Key doesn't support sign"));
            }
        } else if self.context == ENC
            && !algs::KEY_DISTRIBUTION_ALGS.contains(
                &agent
                    .header
                    .alg
                    .ok_or(JsValue::from("Missing recipient algorithm"))?,
            )
        {
            return Err(JsValue::from("Invalid agent algorithm"));
        }
        self.agents.push(agent.clone());
        Ok(())
    }

    pub fn get_agent(&self, kid: Vec<u8>) -> Result<Vec<usize>, JsValue> {
        let mut keys: Vec<usize> = Vec::new();
        for i in 0..self.agents.len() {
            if self.agents[i]
                .header
                .kid
                .as_ref()
                .ok_or(JsValue::from("Missing KID"))?
                == &kid
            {
                keys.push(i);
            }
        }
        Ok(keys)
    }

    pub fn key(&mut self, cose_key: &keys::CoseKey) -> Result<(), JsValue> {
        if self.agents.len() > 0 {
            return Err(JsValue::from("Invalid Operation for Context"));
        }
        cose_key.verify_kty()?;
        if cose_key.alg.ok_or(JsValue::from("Missing Key alg"))?
            != self.header.alg.ok_or(JsValue::from("Missing Header alg"))?
        {
            return Err(JsValue::from("Algorithms don't match"));
        }

        if self.context == SIG {
            self.crv = cose_key.crv;
            if cose_key.key_ops.contains(&keys::KEY_OPS_SIGN) {
                let priv_key = cose_key.get_s_key()?;
                if priv_key.len() > 0 {
                    self.key_encode = true;
                    self.priv_key = priv_key;
                }
            }
            if cose_key.key_ops.contains(&keys::KEY_OPS_VERIFY) {
                let pub_key = cose_key.get_pub_key()?;
                if pub_key.len() > 0 {
                    self.key_decode = true;
                    self.pub_key = pub_key;
                }
            }
        } else {
            if self.context == ENC && self.header.partial_iv != None {
                self.header.iv = Some(algs::gen_iv(
                    &mut self.header.partial_iv.as_mut().unwrap(),
                    cose_key
                        .base_iv
                        .as_ref()
                        .ok_or(JsValue::from("Missing Base IV"))?,
                ));
            }
            let key = cose_key.get_s_key()?;
            if key.len() > 0 {
                if (self.context == ENC && cose_key.key_ops.contains(&keys::KEY_OPS_ENCRYPT))
                    || (self.context == MAC && cose_key.key_ops.contains(&keys::KEY_OPS_MAC))
                {
                    self.key_encode = true;
                }
                if (self.context == ENC && cose_key.key_ops.contains(&keys::KEY_OPS_DECRYPT))
                    || (self.context == MAC && cose_key.key_ops.contains(&keys::KEY_OPS_MAC_VERIFY))
                {
                    self.key_decode = true;
                }
                self.priv_key = key;
            }
        }

        if !self.key_encode && !self.key_decode {
            return Err(JsValue::from("Key has no valid key ops"));
        }
        Ok(())
    }

    pub fn counter_sig(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut CoseAgent,
    ) -> Result<(), JsValue> {
        if self.secured.len() == 0 {
            return Err(JsValue::from(
                "Missing ".to_owned() + MISS_ERR[self.context],
            ));
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.sign(&self.secured, &aead, &self.ph_bstr)?;
            Ok(())
        }
    }

    pub fn get_to_sign(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut CoseAgent,
    ) -> Result<Vec<u8>, JsValue> {
        if self.secured.len() == 0 {
            return Err(JsValue::from(
                "Missing ".to_owned() + MISS_ERR[self.context],
            ));
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.get_to_sign(&self.secured, &aead, &self.ph_bstr)
        }
    }
    pub fn get_to_verify(
        &mut self,
        external_aad: Option<Vec<u8>>,
        counter: usize,
    ) -> Result<Vec<u8>, JsValue> {
        if self.secured.len() == 0 {
            return Err(JsValue::from(
                "Missing ".to_owned() + MISS_ERR[self.context],
            ));
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            self.header.counters[counter].get_to_sign(&self.secured, &aead, &self.ph_bstr)
        }
    }

    pub fn counters_verify(
        &mut self,
        external_aad: Option<Vec<u8>>,
        counter: usize,
    ) -> Result<(), JsValue> {
        let to_sig;
        if self.context == SIG && self.agents.len() > 0 {
            to_sig = &self.payload;
        } else {
            to_sig = &self.secured;
        }
        if to_sig.len() == 0 {
            return Err(JsValue::from(
                "Missing ".to_owned() + MISS_ERR[self.context],
            ));
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            if self.header.counters[counter].verify(to_sig, &aead, &self.ph_bstr)? {
                Ok(())
            } else {
                Err(JsValue::from("Invalid Counter Signature"))
            }
        }
    }

    pub fn add_counter_sig(&mut self, counter: CoseAgent) -> Result<(), JsValue> {
        if !algs::SIGNING_ALGS.contains(&counter.header.alg.ok_or(JsValue::from("Missing alg"))?) {
            return Err(JsValue::from(
                "Invalid algorithm for COUNTER_SIGNATURE context",
            ));
        }
        if counter.context != cose_struct::COUNTER_SIGNATURE {
            return Err(JsValue::from("Invalid context"));
        }
        if self.header.unprotected.contains(&COUNTER_SIG) {
            self.header.counters.push(counter);
            Ok(())
        } else {
            self.header.counters.push(counter);
            self.header.remove_label(COUNTER_SIG);
            self.header.unprotected.push(COUNTER_SIG);
            Ok(())
        }
    }

    pub fn secure_content(&mut self, external_aad: Option<Vec<u8>>) -> Result<(), JsValue> {
        if self.payload.len() <= 0 {
            return Err(JsValue::from("Missing payload"));
        }
        self.ph_bstr = self.header.get_protected_bstr(true)?;
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        if self.agents.len() <= 0 {
            if !self.key_encode {
                return Err(JsValue::from("Key op not supported"));
            }
            let alg = self.header.alg.ok_or(JsValue::from("Missing algorithm"))?;
            if self.context == SIG {
                if !algs::SIGNING_ALGS.contains(&alg) {
                    Err(JsValue::from("Invalid algorithm"))
                } else {
                    self.secured = cose_struct::gen_sig(
                        &self.priv_key,
                        &alg,
                        &self.crv,
                        &aead,
                        cose_struct::SIGNATURE1,
                        &self.ph_bstr,
                        &Vec::new(),
                        &self.payload,
                    )?;
                    Ok(())
                }
            } else if self.context == ENC {
                if !algs::ENCRYPT_ALGS.contains(&alg) {
                    Err(JsValue::from("Invalid algorithm"))
                } else {
                    self.secured = cose_struct::gen_cipher(
                        &self.priv_key,
                        &alg,
                        self.header.iv.as_ref().ok_or(JsValue::from("Missing IV"))?,
                        &aead,
                        cose_struct::ENCRYPT0,
                        &self.ph_bstr,
                        &self.payload,
                    )?;
                    Ok(())
                }
            } else {
                if !algs::MAC_ALGS.contains(&alg) {
                    Err(JsValue::from("Invalid algorithm"))
                } else {
                    self.secured = cose_struct::gen_mac(
                        &self.priv_key,
                        &alg,
                        &aead,
                        cose_struct::MAC0,
                        &self.ph_bstr,
                        &self.payload,
                    )?;
                    Ok(())
                }
            }
        } else {
            if self.context == SIG {
                for i in 0..self.agents.len() {
                    if !algs::SIGNING_ALGS.contains(
                        &self.agents[i]
                            .header
                            .alg
                            .ok_or(JsValue::from("Missing algorithm"))?,
                    ) {
                        return Err(JsValue::from("Invalid Algorithm"));
                    } else if !self.agents[i].key_ops.contains(&keys::KEY_OPS_SIGN) {
                        return Err(JsValue::from("Key op not supported"));
                    } else {
                        self.agents[i].sign(&self.payload, &aead, &self.ph_bstr)?;
                    }
                }
                Ok(())
            } else {
                let alg = self.header.alg.ok_or(JsValue::from("Missing algorithm"))?;
                let mut cek;
                if algs::DIRECT
                    == self.agents[0]
                        .header
                        .alg
                        .ok_or(JsValue::from("Missing algorithm"))?
                {
                    if self.agents.len() > 1 {
                        return Err(JsValue::from("Only one recipient allowed for algorithm"));
                    }
                    if !self.agents[0].key_ops.contains(&KO[self.context][0]) {
                        return Err(JsValue::from("Key op not supported"));
                    } else {
                        if self.context == ENC {
                            self.secured = self.agents[0].enc(
                                &self.payload,
                                &aead,
                                &self.ph_bstr,
                                &alg,
                                self.header.iv.as_ref().ok_or(JsValue::from("Missing IV"))?,
                            )?;
                            return Ok(());
                        } else {
                            self.agents[0].mac(&self.payload, &aead, &self.ph_bstr)?;
                            return Ok(());
                        }
                    }
                } else if algs::ECDH_H.contains(
                    self.agents[0]
                        .header
                        .alg
                        .as_ref()
                        .ok_or(JsValue::from("Missing algorithm"))?,
                ) {
                    if self.agents.len() > 1 {
                        return Err(JsValue::from("Only one recipient allowed for algorithm"));
                    }
                    let size = algs::get_cek_size(&alg)?;
                    cek = self.agents[0].derive_key(&Vec::new(), size, true, &alg)?;
                } else {
                    cek = algs::gen_random_key(&alg)?;
                    for i in 0..self.agents.len() {
                        if algs::DIRECT == self.agents[i].header.alg.unwrap()
                            || algs::ECDH_H.contains(self.agents[i].header.alg.as_ref().unwrap())
                        {
                            return Err(JsValue::from("Only one recipient allowed for algorithm"));
                        }
                        cek = self.agents[i].derive_key(&cek, cek.len(), true, &alg)?;
                    }
                }
                if self.context == ENC {
                    self.secured = cose_struct::gen_cipher(
                        &cek,
                        &alg,
                        self.header.iv.as_ref().ok_or(JsValue::from("Missing IV"))?,
                        &aead,
                        cose_struct::ENCRYPT,
                        &self.ph_bstr,
                        &self.payload,
                    )?;
                    Ok(())
                } else {
                    self.secured = cose_struct::gen_mac(
                        &cek,
                        &alg,
                        &aead,
                        cose_struct::MAC,
                        &self.ph_bstr,
                        &self.payload,
                    )?;
                    Ok(())
                }
            }
        }
    }

    pub fn encode(&mut self, data: bool) -> Result<Vec<u8>, JsValue> {
        if self.agents.len() <= 0 {
            if self.secured.len() <= 0 {
                return Err(JsValue::from(
                    "Missing ".to_owned() + MISS_ERR[self.context],
                ));
            } else {
                let mut e = Encoder::new();
                e.tag(TAGS[self.context][0])?;
                e.array(SIZES[self.context][0]);
                e.bytes(self.ph_bstr.as_slice());
                self.header.encode_unprotected(&mut e)?;
                if data {
                    if self.context == ENC {
                        e.bytes(self.secured.as_slice());
                    } else {
                        e.bytes(self.payload.as_slice());
                    }
                } else {
                    e.null();
                }
                if self.context != ENC {
                    e.bytes(self.secured.as_slice());
                }
                self.bytes = e.encoded();
                self.header.labels_found = Vec::new();
            }
        } else {
            let mut e = Encoder::new();
            e.tag(TAGS[self.context][1])?;
            e.array(SIZES[self.context][1]);
            e.bytes(self.ph_bstr.as_slice());
            self.header.encode_unprotected(&mut e)?;
            if data {
                if self.context == ENC {
                    e.bytes(self.secured.as_slice());
                } else {
                    e.bytes(self.payload.as_slice());
                }
            } else {
                e.null();
            }
            if self.context == MAC {
                e.bytes(self.secured.as_slice());
            }
            let r_len = self.agents.len();
            e.array(r_len);
            for i in 0..r_len {
                self.agents[i].encode(&mut e)?;
            }
            self.bytes = e.encoded();
            self.header.labels_found = Vec::new();
        }
        Ok(self.bytes.clone())
    }

    pub fn init_decoder(&mut self, data: Option<Vec<u8>>) -> Result<(), JsValue> {
        let input = self.bytes.clone();
        let mut d = Decoder::new(input);
        let mut tag: Option<u32> = None;

        match d.tag() {
            Ok(value) => {
                if !TAGS[self.context].contains(&value) {
                    return Err(JsValue::from("Invalid Tag"));
                } else {
                    tag = Some(value);
                    d.array()?;
                }
            }
            Err(_) => match d.array() {
                Ok(v) => {
                    if v != SIZES[self.context][0] && v != SIZES[self.context][1] {
                        return Err(JsValue::from("Invalid COSE structure"));
                    }
                }
                Err(_) => {
                    return Err(JsValue::from("Invalid COSE structure"));
                }
            },
        };

        match d.bytes() {
            Ok(v) => {
                self.ph_bstr = v;
            }
            Err(_) => match d.object() {
                Ok(v1) => {
                    if v1 == 0 {
                        self.ph_bstr = Vec::new();
                    } else {
                        return Err(JsValue::from("Invalid cose structure"));
                    }
                }
                Err(_) => {
                    return Err(JsValue::from("Invalid cose structure"));
                }
            },
        }
        if self.ph_bstr.len() > 0 {
            self.header.decode_protected_bstr(self.ph_bstr.clone())?;
        }
        self.header.decode_unprotected(&mut d, false)?;
        self.header.labels_found = Vec::new();

        match data {
            None => {
                if self.context == ENC {
                    self.secured = d.bytes()?
                } else {
                    self.payload = d.bytes()?
                }
            }
            Some(v) => {
                d.skip();
                if self.context == ENC {
                    self.secured = v;
                } else {
                    self.payload = v;
                }
            }
        };

        if (self.context == ENC && self.secured.len() <= 0)
            || (self.context != ENC && self.payload.len() <= 0)
        {
            if self.context == ENC {
                return Err(JsValue::from("Missing Ciphertext"));
            } else {
                return Err(JsValue::from("Missing Payload"));
            }
        }

        if self.context != SIG {
            if self.header.alg.ok_or(JsValue::from("Missing algorithm"))? == algs::DIRECT
                && self.ph_bstr.len() > 0
            {
                return Err(JsValue::from("Invalid COSE structure"));
            } else if algs::A_KW.contains(
                self.header
                    .alg
                    .as_ref()
                    .ok_or(JsValue::from("Missing algorithm"))?,
            ) && self.ph_bstr.len() > 0
            {
                return Err(JsValue::from("Invalid COSE structure"));
            }
        }

        if self.context == MAC {
            self.secured = d.bytes()?.to_vec();
            if self.secured.len() <= 0 {
                return Err(JsValue::from("Missing payload"));
            }
        }
        match d.array() {
            Ok(value) => {
                if tag == None || tag.unwrap() == TAGS[self.context][1] {
                    for _ in 0..value {
                        let mut agent = CoseAgent::new();
                        agent.context = CONTEXTS[self.context].to_string();
                        d.array()?;
                        match d.bytes() {
                            Ok(v) => {
                                agent.ph_bstr = v;
                            }
                            Err(_) => match d.object() {
                                Ok(v1) => {
                                    if v1 == 0 {
                                        agent.ph_bstr = Vec::new();
                                    } else {
                                        return Err(JsValue::from("Invalid cose structure"));
                                    }
                                }
                                Err(_) => {
                                    return Err(JsValue::from("Invalid cose structure"));
                                }
                            },
                        }
                        agent.decode(&mut d)?;
                        self.agents.push(agent);
                    }
                } else {
                    return Err(JsValue::from("Invalid COSE tag"));
                }
            }
            Err(_) => {
                if self.context == SIG {
                    if tag == None || tag.unwrap() == TAGS[self.context][0] {
                        match d.bytes() {
                            Ok(v) => {
                                if self.context == SIG {
                                    self.secured = v;
                                } else {
                                    return Err(JsValue::from("Invalid COSE Structure"));
                                }
                            }
                            Err(_) => {
                                return Err(JsValue::from("Invalid COSE Structure"));
                            }
                        }
                    } else {
                        return Err(JsValue::from("Invalid COSE tag"));
                    }
                }
                if self.secured.len() <= 0 {
                    return Err(JsValue::from(
                        "Missing ".to_owned() + MISS_ERR[self.context],
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn decode(
        &mut self,
        external_aad: Option<Vec<u8>>,
        agent: Option<usize>,
    ) -> Result<Vec<u8>, JsValue> {
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        if self.agents.len() <= 0 {
            if !self.key_decode {
                return Err(JsValue::from("Key op not supported"));
            } else {
                if self.context == SIG {
                    if !cose_struct::verify_sig(
                        &self.pub_key,
                        &self.header.alg.ok_or(JsValue::from("Missing algorithm"))?,
                        &self.crv,
                        &aead,
                        cose_struct::SIGNATURE1,
                        &self.ph_bstr,
                        &Vec::new(),
                        &self.payload,
                        &self.secured,
                    )? {
                        Err(JsValue::from("Invalid Signature"))
                    } else {
                        Ok(self.payload.clone())
                    }
                } else if self.context == MAC {
                    if !cose_struct::verify_mac(
                        &self.priv_key,
                        &self.header.alg.ok_or(JsValue::from("Missing algorithm"))?,
                        &aead,
                        cose_struct::MAC0,
                        &self.ph_bstr,
                        &self.secured,
                        &self.payload,
                    )? {
                        return Err(JsValue::from("Invalid MAC tag"));
                    } else {
                        Ok(self.payload.clone())
                    }
                } else {
                    Ok(cose_struct::dec_cipher(
                        &self.priv_key,
                        &self.header.alg.ok_or(JsValue::from("Missing algorithm"))?,
                        self.header.iv.as_ref().ok_or(JsValue::from("Missing IV"))?,
                        &aead,
                        cose_struct::ENCRYPT0,
                        &self.ph_bstr,
                        &self.secured,
                    )?)
                }
            }
        } else if agent != None {
            let index = agent.ok_or(JsValue::from("Missing Agent"))?;
            if self.context == SIG {
                if self.agents[index].pub_key.len() == 0
                    && !self.agents[index].key_ops.contains(&keys::KEY_OPS_VERIFY)
                {
                    Err(JsValue::from("Key Op not supported"))
                } else {
                    if !self.agents[index].verify(&self.payload, &aead, &self.ph_bstr)? {
                        Err(JsValue::from("Invalid Signature"))
                    } else {
                        Ok(self.payload.clone())
                    }
                }
            } else {
                let alg = self.header.alg.ok_or(JsValue::from("Missing algorithm"))?;
                let cek;
                if algs::DIRECT
                    == self.agents[index]
                        .header
                        .alg
                        .ok_or(JsValue::from("Missing algorithm"))?
                {
                    if !self.agents[index].key_ops.contains(&KO[self.context][1]) {
                        return Err(JsValue::from("Key op not supported"));
                    } else {
                        if self.agents[index].s_key.len() > 0 {
                            cek = self.agents[index].s_key.clone();
                        } else {
                            return Err(JsValue::from("Key op not supported"));
                        }
                    }
                } else {
                    let size = algs::get_cek_size(&alg)?;
                    let payload = self.agents[index].payload.clone();
                    cek = self.agents[index].derive_key(&payload, size, false, &alg)?;
                }
                if self.context == ENC {
                    Ok(cose_struct::dec_cipher(
                        &cek,
                        &alg,
                        self.header.iv.as_ref().ok_or(JsValue::from("Missing IV"))?,
                        &aead,
                        cose_struct::ENCRYPT,
                        &self.ph_bstr,
                        &self.secured,
                    )?)
                } else {
                    if !cose_struct::verify_mac(
                        &cek,
                        &alg,
                        &aead,
                        cose_struct::MAC,
                        &self.ph_bstr,
                        &self.secured,
                        &self.payload,
                    )? {
                        Err(JsValue::from("Invalid MAC tag"))
                    } else {
                        Ok(self.payload.clone())
                    }
                }
            }
        } else {
            return Err(JsValue::from("Missing Agent"));
        }
    }
}
