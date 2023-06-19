use crate::agent::CoseAgent;
use crate::algs;
use crate::cbor::{Decoder, Encoder};
use crate::common;
use crate::enc_struct;
use crate::headers;
use crate::keys;
use crate::mac_struct;
use crate::sig_struct;
use wasm_bindgen::prelude::*;

const SIZE: usize = 4;
const SIZE_N: usize = 5;
const MAC_TAGS: [u32; 2] = [common::MAC0_TAG, common::MAC_TAG];

#[wasm_bindgen]
pub struct CoseMAC {
    pub(crate) header: headers::CoseHeader,
    tag: Vec<u8>,
    pub(crate) payload: Vec<u8>,
    pub(crate) bytes: Vec<u8>,
    ph_bstr: Vec<u8>,
    key: Vec<u8>,
    sign: bool,
    verify: bool,
    pub(crate) recipients: Vec<CoseAgent>,
}

#[wasm_bindgen]
impl CoseMAC {
    #[wasm_bindgen(constructor)]
    pub fn new() -> CoseMAC {
        CoseMAC {
            bytes: Vec::new(),
            header: headers::CoseHeader::new(),
            tag: Vec::new(),
            payload: Vec::new(),
            ph_bstr: Vec::new(),
            key: Vec::new(),
            sign: false,
            verify: false,
            recipients: Vec::new(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn header(&self) -> headers::CoseHeader {
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
    pub fn counter_header(&self, i: usize) -> headers::CoseHeader {
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
    pub fn recipient_header(&self, i: usize) -> headers::CoseHeader {
        self.recipients[i].header.clone()
    }

    pub fn set_header(&mut self, header: headers::CoseHeader) {
        self.header = header;
    }

    pub fn set_bytes(&mut self, bytes: Vec<u8>) {
        self.bytes = bytes;
    }
    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    pub fn add_recipient(&mut self, recipient: &mut CoseAgent) -> Result<(), JsValue> {
        recipient.context = enc_struct::MAC_RECIPIENT.to_string();
        self.recipients.push(recipient.clone());
        Ok(())
    }

    pub fn get_recipient(&self, kid: Vec<u8>) -> Result<Vec<usize>, JsValue> {
        let mut keys: Vec<usize> = Vec::new();
        for i in 0..self.recipients.len() {
            if *self.recipients[i]
                .header
                .kid
                .as_ref()
                .ok_or(JsValue::from("Missing kid"))?
                == kid
            {
                keys.push(i);
            }
        }
        Ok(keys)
    }

    pub fn add_recipient_key(
        &mut self,
        recipient: usize,
        key: &keys::CoseKey,
    ) -> Result<(), JsValue> {
        self.recipients[recipient].key(key)
    }

    pub fn counter_sig(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut CoseAgent,
    ) -> Result<(), JsValue> {
        if self.tag.len() == 0 {
            Err(JsValue::from("Missing Tag"))
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.sign(&self.tag, &aead, &self.ph_bstr)?;
            Ok(())
        }
    }

    pub fn get_to_sign(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut CoseAgent,
    ) -> Result<Vec<u8>, JsValue> {
        if self.tag.len() == 0 {
            Err(JsValue::from("Missing Tag"))
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.get_to_sign(&self.tag, &aead, &self.ph_bstr)
        }
    }

    pub fn get_to_verify(
        &mut self,
        external_aad: Option<Vec<u8>>,
        counter: usize,
    ) -> Result<Vec<u8>, JsValue> {
        if self.tag.len() == 0 {
            Err(JsValue::from("Missing Tag"))
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            self.header.counters[counter].get_to_sign(&self.tag, &aead, &self.ph_bstr)
        }
    }

    pub fn counters_verify(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: usize,
    ) -> Result<(), JsValue> {
        if self.tag.len() == 0 {
            Err(JsValue::from("Invalid cose structure"))
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            if self.header.counters[counter].verify(&self.tag, &aead, &self.ph_bstr)? {
                Ok(())
            } else {
                Err(JsValue::from("Invalid Counter Signature"))
            }
        }
    }

    pub fn add_counter_sig(&mut self, counter: CoseAgent) -> Result<(), JsValue> {
        if !algs::SIGNING_ALGS.contains(&counter.header.alg.ok_or(JsValue::from("Missing alg"))?) {
            return Err(JsValue::from("Invalid alg"));
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

    pub fn key(&mut self, cose_key: &keys::CoseKey) -> Result<(), JsValue> {
        if self.recipients.len() > 0 {
            return Err(JsValue::from("Invalid method for context"));
        }
        cose_key.verify_kty()?;
        let key = cose_key.get_s_key()?;
        if cose_key.alg.ok_or(JsValue::from("Missing Key alg"))?
            != self.header.alg.ok_or(JsValue::from("Missing Header alg"))?
        {
            return Err(JsValue::from("Algorithms don't match"));
        }
        if key.len() > 0 {
            if cose_key.key_ops.contains(&keys::KEY_OPS_MAC) {
                self.sign = true;
            }
            if cose_key.key_ops.contains(&keys::KEY_OPS_MAC_VERIFY) {
                self.verify = true;
            }
            self.key = key;
        }
        if !self.sign && !self.verify {
            return Err(JsValue::from("Key doesn't have KeyOp mac or mac_verify"));
        }
        Ok(())
    }

    pub fn gen_tag(&mut self, external_aad: Option<Vec<u8>>) -> Result<(), JsValue> {
        if self.payload.len() <= 0 {
            return Err(JsValue::from("Missing payload"));
        }
        self.ph_bstr = self.header.get_protected_bstr(true)?;
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        let alg = &self.header.alg.ok_or(JsValue::from("Missing alg"))?;
        if self.recipients.len() <= 0 {
            if !algs::MAC_ALGS.contains(&alg) {
                return Err(JsValue::from("Invalid alg"));
            } else if !self.sign {
                Err(JsValue::from("Key doesn't support MAC"))
            } else {
                self.tag = mac_struct::gen_mac(
                    &self.key,
                    &alg,
                    &aead,
                    mac_struct::MAC0,
                    &self.ph_bstr,
                    &self.payload,
                )?;
                Ok(())
            }
        } else {
            let mut cek;
            if algs::DIRECT
                == self.recipients[0]
                    .header
                    .alg
                    .ok_or(JsValue::from("Missing alg"))?
            {
                if self.recipients.len() > 1 {
                    return Err(JsValue::from("Only 1 recipient allowed for DIRECT alg"));
                }
                if !self.recipients[0].key_ops.contains(&keys::KEY_OPS_MAC) {
                    return Err(JsValue::from("Key doesn't support MAC"));
                } else {
                    self.recipients[0].sign(&self.payload, &aead, &self.ph_bstr)?;
                    return Ok(());
                }
            } else if algs::ECDH_H.contains(
                self.recipients[0]
                    .header
                    .alg
                    .as_ref()
                    .ok_or(JsValue::from("Missing alg"))?,
            ) {
                if self.recipients.len() > 1 {
                    return Err(JsValue::from("Only 1 recipient allowed for ECDH_HKDF algs"));
                }
                let size = algs::get_cek_size(&alg)?;
                cek = self.recipients[0].derive_key(&Vec::new(), size, true, &alg)?;
            } else {
                cek = algs::gen_random_key(&alg)?;
                for i in 0..self.recipients.len() {
                    if algs::DIRECT
                        == self.recipients[i]
                            .header
                            .alg
                            .ok_or(JsValue::from("Missing alg"))?
                        || algs::ECDH_H.contains(
                            self.recipients[i]
                                .header
                                .alg
                                .as_ref()
                                .ok_or(JsValue::from("Missing alg"))?,
                        )
                    {
                        return Err(JsValue::from("Invalid alg"));
                    }
                    cek = self.recipients[i].derive_key(&cek, cek.len(), true, &alg)?;
                }
            }
            self.tag = mac_struct::gen_mac(
                &cek,
                &alg,
                &aead,
                mac_struct::MAC,
                &self.ph_bstr,
                &self.payload,
            )?;
            Ok(())
        }
    }

    pub fn encode(&mut self, payload: bool) -> Result<(), JsValue> {
        if self.recipients.len() <= 0 {
            let mut e = Encoder::new();
            e.tag(common::MAC0_TAG)?;
            e.array(SIZE);
            e.bytes(self.ph_bstr.as_slice());
            self.header.encode_unprotected(&mut e)?;
            if payload {
                e.bytes(self.payload.as_slice());
            } else {
                e.null();
            }
            e.bytes(self.tag.as_slice());
            self.bytes = e.encoded();
            self.header.labels_found = Vec::new();
            Ok(())
        } else {
            let mut e = Encoder::new();
            e.tag(common::MAC_TAG)?;
            e.array(SIZE_N);
            e.bytes(self.ph_bstr.as_slice());
            self.header.encode_unprotected(&mut e)?;
            if payload {
                e.bytes(self.payload.as_slice());
            } else {
                e.null();
            }
            e.bytes(self.tag.as_slice());
            let r_len = self.recipients.len();
            e.array(r_len);
            for i in 0..r_len {
                self.recipients[i].encode(&mut e)?;
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
            Ok(v) => {
                if !MAC_TAGS.contains(&v) {
                    return Err(JsValue::from("Invalid tag"));
                } else {
                    tag = Some(v);
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
            Ok(value) => self.ph_bstr = value,
            Err(_) => match d.object() {
                Ok(v) => {
                    if v == 0 {
                        self.ph_bstr = Vec::new();
                    } else {
                        return Err(JsValue::from("Invalid cose structure"));
                    }
                }
                Err(_) => return Err(JsValue::from("Invalid cose structure")),
            },
        }
        if self.ph_bstr.len() > 0 {
            self.header.decode_protected_bstr(self.ph_bstr.clone())?;
        }
        self.header.decode_unprotected(&mut d, false)?;
        self.header.labels_found = Vec::new();

        if payload == None {
            self.payload = d.bytes()?.to_vec();
        } else {
            self.payload = payload.unwrap();
            d.skip();
        }
        self.tag = d.bytes()?.to_vec();
        if self.tag.len() <= 0 {
            return Err(JsValue::from("Invalid cose structure"));
        }

        let mut r_len = 0;
        let is_mac0 = match d.array() {
            Ok(v) => {
                r_len = v;
                false
            }
            Err(_) => true,
        };

        if !is_mac0 && (tag == None || tag.unwrap() == common::MAC_TAG) {
            let mut recipient: CoseAgent;
            for _ in 0..r_len {
                recipient = CoseAgent::new();
                recipient.context = enc_struct::MAC_RECIPIENT.to_string();
                d.array()?;
                match d.bytes() {
                    Ok(value) => recipient.ph_bstr = value,
                    Err(_) => match d.object() {
                        Ok(v) => {
                            if v == 0 {
                                recipient.ph_bstr = Vec::new();
                            } else {
                                return Err(JsValue::from("Invalid cose structure"));
                            }
                        }
                        Err(_) => return Err(JsValue::from("Invalid cose structure")),
                    },
                }
                recipient.decode(&mut d)?;
                self.recipients.push(recipient);
            }
        } else if is_mac0 && (tag == None || tag.unwrap() == common::MAC0_TAG) {
            if self.tag.len() <= 0 {
                return Err(JsValue::from("Invalid cose structure"));
            }
        }
        Ok(())
    }

    pub fn decode(
        &mut self,
        external_aad: Option<Vec<u8>>,
        recipient: Option<usize>,
    ) -> Result<(), JsValue> {
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        let alg = self.header.alg.ok_or(JsValue::from("Missing alg"))?;
        if self.recipients.len() <= 0 {
            if !self.verify {
                return Err(JsValue::from("Key doesn't support mac_verify operation"));
            } else {
                if !mac_struct::verify_mac(
                    &self.key,
                    &alg,
                    &aead,
                    mac_struct::MAC0,
                    &self.ph_bstr,
                    &self.tag,
                    &self.payload,
                )? {
                    return Err(JsValue::from("Invalid MAC"));
                } else {
                    Ok(())
                }
            }
        } else if recipient != None {
            let cek;
            let index = recipient.ok_or(JsValue::from("recipient missing"))?;
            if algs::DIRECT
                == self.recipients[index]
                    .header
                    .alg
                    .ok_or(JsValue::from("Missing alg"))?
            {
                if !self.recipients[index]
                    .key_ops
                    .contains(&keys::KEY_OPS_MAC_VERIFY)
                {
                    return Err(JsValue::from("Key doesn't support mac_verify"));
                } else {
                    if self.recipients[index].s_key.len() > 0 {
                        cek = self.recipients[index].s_key.clone();
                    } else {
                        return Err(JsValue::from("Missing key"));
                    }
                }
            } else {
                let size = algs::get_cek_size(&alg)?;
                let payload = self.recipients[index].payload.clone();
                cek = self.recipients[index].derive_key(&payload, size, false, &alg)?;
            }
            if !mac_struct::verify_mac(
                &cek,
                &alg,
                &aead,
                mac_struct::MAC,
                &self.ph_bstr,
                &self.tag,
                &self.payload,
            )? {
                return Err(JsValue::from("Invalid MAC"));
            }
            Ok(())
        } else {
            return Err(JsValue::from("Missing recipient"));
        }
    }
}
