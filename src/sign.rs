use crate::agent::CoseAgent;
use crate::algs;
use crate::cbor::{Decoder, Encoder};
use crate::common;
use crate::headers;
use crate::keys;
use crate::sig_struct;
use wasm_bindgen::prelude::*;

const SIZE: usize = 4;
const SIG_TAGS: [u32; 2] = [common::SIG1_TAG, common::SIG_TAG];

#[wasm_bindgen]
pub struct CoseSign {
    pub(crate) header: headers::CoseHeader,
    pub(crate) payload: Vec<u8>,
    signature: Vec<u8>,
    pub(crate) bytes: Vec<u8>,
    ph_bstr: Vec<u8>,
    pub_key: Vec<u8>,
    priv_key: Vec<u8>,
    sign: bool,
    verify: bool,
    pub(crate) signers: Vec<CoseAgent>,
}

#[wasm_bindgen]
impl CoseSign {
    #[wasm_bindgen(constructor)]
    pub fn new() -> CoseSign {
        CoseSign {
            bytes: Vec::new(),
            header: headers::CoseHeader::new(),
            payload: Vec::new(),
            signature: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            priv_key: Vec::new(),
            sign: false,
            verify: false,
            signers: Vec::new(),
        }
    }

    pub fn add_header(&mut self, header: headers::CoseHeader) {
        self.header = header;
    }

    pub fn payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn set_bytes(&mut self, bytes: Vec<u8>) {
        self.bytes = bytes;
    }

    pub fn add_signer(&mut self, signer: &mut CoseAgent) -> Result<(), JsValue> {
        signer.context = sig_struct::SIGNATURE.to_string();
        if !algs::SIGNING_ALGS.contains(&signer.header.alg.ok_or(JsValue::from("Missing alg"))?) {
            return Err(JsValue::from("Invalid algorithm for SIGNATURE context"));
        }
        if !signer.key_ops.contains(&keys::KEY_OPS_SIGN) {
            return Err(JsValue::from("Key doesn't support sign"));
        }
        self.signers.push(signer.clone());
        Ok(())
    }

    pub fn get_signer(&self, kid: Vec<u8>) -> Result<Vec<usize>, JsValue> {
        let mut keys: Vec<usize> = Vec::new();
        for i in 0..self.signers.len() {
            if self.signers[i]
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

    pub fn add_signer_key(
        &mut self,
        index: usize,
        cose_key: &keys::CoseKey,
    ) -> Result<(), JsValue> {
        if index < self.signers.len() {
            self.signers[index].key(cose_key)?;
            Ok(())
        } else {
            Err(JsValue::from("Invalid index provided"))
        }
    }

    pub fn key(&mut self, cose_key: &keys::CoseKey) -> Result<(), JsValue> {
        if self.signers.len() > 0 {
            return Err(JsValue::from("Invalid Operation for SIGNATURE1 Context"));
        }
        cose_key.verify_kty()?;
        if cose_key.alg.ok_or(JsValue::from("Missing Key alg"))?
            != self.header.alg.ok_or(JsValue::from("Missing Header alg"))?
        {
            return Err(JsValue::from("Algorithms don't match"));
        }

        if cose_key.key_ops.contains(&keys::KEY_OPS_SIGN) {
            let priv_key = cose_key.get_s_key()?;
            if priv_key.len() > 0 {
                self.sign = true;
                self.priv_key = priv_key;
            }
        }
        if cose_key.key_ops.contains(&keys::KEY_OPS_VERIFY) {
            let pub_key =
                cose_key.get_pub_key(self.header.alg.ok_or(JsValue::from("Missing alg"))?)?;
            if pub_key.len() > 0 {
                self.verify = true;
                self.pub_key = pub_key;
            }
        }

        if !self.sign && !self.verify {
            return Err(JsValue::from("Key unable to sign or verify"));
        }
        Ok(())
    }

    pub fn counter_sig(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut CoseAgent,
    ) -> Result<(), JsValue> {
        if self.signature.len() == 0 {
            return Err(JsValue::from("Missing signature"));
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.sign(&self.signature, &aead, &self.ph_bstr)?;
            Ok(())
        }
    }

    pub fn get_to_sign(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut CoseAgent,
    ) -> Result<Vec<u8>, JsValue> {
        if self.signature.len() == 0 {
            return Err(JsValue::from("Missing signature"));
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.get_to_sign(&self.signature, &aead, &self.ph_bstr)
        }
    }
    pub fn get_to_verify(
        &mut self,
        external_aad: Option<Vec<u8>>,
        counter: usize,
    ) -> Result<Vec<u8>, JsValue> {
        if self.signature.len() == 0 {
            return Err(JsValue::from("Missing signature"));
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            self.header.counters[counter].get_to_sign(&self.signature, &aead, &self.ph_bstr)
        }
    }

    pub fn counters_verify(
        &mut self,
        external_aad: Option<Vec<u8>>,
        counter: usize,
    ) -> Result<(), JsValue> {
        let signature;
        if self.signers.len() > 0 {
            signature = &self.payload;
        } else {
            signature = &self.signature;
        }
        if signature.len() == 0 {
            return Err(JsValue::from("Missing signature"));
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            if self.header.counters[counter].verify(signature, &aead, &self.ph_bstr)? {
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
        if counter.context != sig_struct::COUNTER_SIGNATURE {
            return Err(JsValue::from("Invalid context"));
        }
        if self.header.unprotected.contains(&headers::COUNTER_SIG) {
            self.header.counters.push(counter);
            Ok(())
        } else {
            self.header.counters.push(counter);
            self.header.remove_label(headers::COUNTER_SIG);
            self.header.unprotected.push(headers::COUNTER_SIG);
            Ok(())
        }
    }

    pub fn gen_signature(&mut self, external_aad: Option<Vec<u8>>) -> Result<(), JsValue> {
        if self.payload.len() <= 0 {
            return Err(JsValue::from("Missing Payload"));
        }
        self.ph_bstr = self.header.get_protected_bstr(true)?;
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        if self.signers.len() <= 0 {
            if !algs::SIGNING_ALGS.contains(&self.header.alg.ok_or(JsValue::from("Missing alg"))?) {
                Err(JsValue::from("Invalid algorithm for SIGNATURE1 context"))
            } else if !self.sign {
                return Err(JsValue::from("Key doesn't support sign operation"));
            } else {
                self.signature = sig_struct::gen_sig(
                    &self.priv_key,
                    &self.header.alg.unwrap(),
                    &aead,
                    sig_struct::SIGNATURE1,
                    &self.ph_bstr,
                    &Vec::new(),
                    &self.payload,
                )?;
                Ok(())
            }
        } else {
            for i in 0..self.signers.len() {
                if !algs::SIGNING_ALGS.contains(
                    &self.signers[i]
                        .header
                        .alg
                        .ok_or(JsValue::from("Missing alg"))?,
                ) {
                    return Err(JsValue::from("Invalid alg"));
                } else if !self.signers[i].key_ops.contains(&keys::KEY_OPS_SIGN) {
                    return Err(JsValue::from("Key doesn't support sign operation"));
                } else {
                    self.signers[i].sign(&self.payload, &aead, &self.ph_bstr)?;
                }
            }
            Ok(())
        }
    }

    pub fn encode(&mut self, payload: bool) -> Result<(), JsValue> {
        if self.signers.len() <= 0 {
            if self.signature.len() <= 0 {
                return Err(JsValue::from("Missing signature"));
            } else {
                let mut e = Encoder::new();
                e.tag(common::SIG1_TAG)?;
                e.array(SIZE);
                e.bytes(self.ph_bstr.as_slice());
                self.header.encode_unprotected(&mut e)?;
                if payload {
                    e.bytes(self.payload.as_slice());
                } else {
                    e.null();
                }
                e.bytes(self.signature.as_slice());
                self.bytes = e.encoded();
                self.header.labels_found = Vec::new();
                Ok(())
            }
        } else {
            let mut e = Encoder::new();
            e.tag(common::SIG_TAG)?;
            e.array(SIZE);
            e.bytes(self.ph_bstr.as_slice());
            self.header.encode_unprotected(&mut e)?;
            if payload {
                e.bytes(self.payload.as_slice());
            } else {
                e.null();
            }
            let r_len = self.signers.len();
            e.array(r_len);
            for i in 0..r_len {
                self.signers[i].encode(&mut e)?;
            }
            self.bytes = e.encoded();
            self.header.labels_found = Vec::new();
            Ok(())
        }
    }

    pub fn init_decoder(&mut self, payload: Option<Vec<u8>>) -> Result<(), JsValue> {
        let input = self.bytes.clone();
        let mut d = Decoder::new(input);
        let mut tag: Option<u32> = None;

        match d.tag() {
            Ok(value) => {
                if !SIG_TAGS.contains(&value) {
                    return Err(JsValue::from("Invalid Tag"));
                } else {
                    tag = Some(value);
                    d.array()?;
                }
            }
            Err(_) => match d.array() {
                Ok(v) => {
                    if v != SIZE {
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

        self.payload = match payload {
            None => d.bytes()?,
            Some(v) => {
                d.skip();
                v
            }
        };
        if self.payload.len() <= 0 {
            return Err(JsValue::from("Payload missing"));
        }

        match d.array() {
            Ok(value) => {
                if tag == None || tag.unwrap() == common::SIG_TAG {
                    let mut signer: CoseAgent;
                    for _ in 0..value {
                        signer = CoseAgent::new();
                        signer.context = sig_struct::SIGNATURE.to_string();
                        d.array()?;
                        match d.bytes() {
                            Ok(v) => {
                                signer.ph_bstr = v;
                            }
                            Err(_) => match d.object() {
                                Ok(v1) => {
                                    if v1 == 0 {
                                        signer.ph_bstr = Vec::new();
                                    } else {
                                        return Err(JsValue::from("Invalid cose structure"));
                                    }
                                }
                                Err(_) => {
                                    return Err(JsValue::from("Invalid cose structure"));
                                }
                            },
                        }
                        signer.decode(&mut d)?;
                        self.signers.push(signer);
                    }
                } else {
                    return Err(JsValue::from("Invalid COSE tag"));
                }
            }
            Err(_) => {
                if tag == None || tag.unwrap() == common::SIG1_TAG {
                    match d.bytes() {
                        Ok(v) => {
                            if v.len() != 0 {
                                self.signature = v;
                            } else {
                                return Err(JsValue::from("Signature missing"));
                            }
                        }
                        Err(_) => {
                            return Err(JsValue::from("Invalid signature value"));
                        }
                    }
                } else {
                    return Err(JsValue::from("Invalid COSE tag"));
                }
            }
        }
        Ok(())
    }

    pub fn decode(
        &mut self,
        external_aad: Option<Vec<u8>>,
        signer: Option<usize>,
    ) -> Result<(), JsValue> {
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        if self.signers.len() <= 0 {
            if !self.verify {
                return Err(JsValue::from("Key doesn't support verify operation"));
            } else {
                if sig_struct::verify_sig(
                    &self.pub_key,
                    &self.header.alg.ok_or(JsValue::from("Missing alg"))?,
                    &aead,
                    sig_struct::SIGNATURE1,
                    &self.ph_bstr,
                    &Vec::new(),
                    &self.payload,
                    &self.signature,
                )? {
                    return Ok(());
                } else {
                    return Err(JsValue::from("Invalid algorithm"));
                }
            }
        } else if signer != None {
            let index = signer.ok_or(JsValue::from("Missing signer"))?;
            if self.signers[index].pub_key.len() <= 0
                && !self.signers[index].key_ops.contains(&keys::KEY_OPS_VERIFY)
            {
                return Err(JsValue::from("Key doesn't support verify operation"));
            } else {
                if !self.signers[index].verify(&self.payload, &aead, &self.ph_bstr)? {
                    return Err(JsValue::from("Invalid algorithm"));
                }
            }
        } else {
            return Err(JsValue::from("Missing Signer"));
        }
        Ok(())
    }
}
