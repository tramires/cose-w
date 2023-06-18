use crate::agent::CoseAgent;
use crate::algs;
use crate::cbor::{Decoder, Encoder};
use crate::common;
use crate::enc_struct;
use crate::headers;
use crate::keys;
use crate::sig_struct;
use wasm_bindgen::prelude::*;

const SIZE: usize = 3;
const SIZE_N: usize = 4;
const ENC_TAGS: [u32; 2] = [common::ENC0_TAG, common::ENC_TAG];

#[wasm_bindgen]
pub struct CoseEncrypt {
    pub(crate) header: headers::CoseHeader,
    ciphertext: Vec<u8>,
    payload: Vec<u8>,
    pub(crate) bytes: Vec<u8>,
    ph_bstr: Vec<u8>,
    key: Vec<u8>,
    enc: bool,
    dec: bool,
    pub(crate) recipients: Vec<CoseAgent>,
}

#[wasm_bindgen]
impl CoseEncrypt {
    #[wasm_bindgen(constructor)]
    pub fn new() -> CoseEncrypt {
        CoseEncrypt {
            bytes: Vec::new(),
            header: headers::CoseHeader::new(),
            ciphertext: Vec::new(),
            payload: Vec::new(),
            ph_bstr: Vec::new(),
            key: Vec::new(),
            enc: false,
            dec: false,
            recipients: Vec::new(),
        }
    }

    pub fn add_header(&mut self, header: headers::CoseHeader) {
        self.header = header;
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn set_bytes(&mut self, bytes: Vec<u8>) {
        self.bytes = bytes;
    }

    pub fn payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    pub fn add_recipient(&mut self, recipient: &mut CoseAgent) -> Result<(), JsValue> {
        recipient.context = enc_struct::ENCRYPT_RECIPIENT.to_string();
        if !algs::KEY_DISTRIBUTION_ALGS
            .contains(&recipient.header.alg.ok_or(JsValue::from("Missing alg"))?)
        {
            return Err(JsValue::from("Invalid method for alg"));
        }
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

    pub fn key(&mut self, cose_key: &keys::CoseKey) -> Result<(), JsValue> {
        if self.recipients.len() > 0 {
            return Err(JsValue::from("Invalid method for context"));
        }
        cose_key.verify_kty()?;
        if cose_key.alg.ok_or(JsValue::from("Missing Key alg"))?
            != self.header.alg.ok_or(JsValue::from("Missing Header alg"))?
        {
            return Err(JsValue::from("Key and header algs don't match"));
        }
        if self.header.partial_iv != None {
            self.header.iv = Some(algs::gen_iv(
                self.header
                    .partial_iv
                    .as_mut()
                    .ok_or(JsValue::from("Missing partial iv"))?,
                cose_key
                    .base_iv
                    .as_ref()
                    .ok_or(JsValue::from("Missing base iv"))?,
            ));
        }

        let key = cose_key.get_s_key()?;
        if key.len() > 0 {
            if cose_key.key_ops.contains(&keys::KEY_OPS_ENCRYPT) {
                self.enc = true;
            }
            if cose_key.key_ops.contains(&keys::KEY_OPS_DECRYPT) {
                self.dec = true;
            }
            self.key = key;
        }
        if !self.enc && !self.dec {
            return Err(JsValue::from(
                "Key doesn't support KeyOp encrypt or decrypt",
            ));
        }
        Ok(())
    }

    pub fn counter_sig(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut CoseAgent,
    ) -> Result<(), JsValue> {
        if self.ciphertext.len() == 0 {
            return Err(JsValue::from("Missing ciphertext"));
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.sign(&self.ciphertext, &aead, &self.ph_bstr)?;
            Ok(())
        }
    }

    pub fn get_to_verify(
        &mut self,
        external_aad: Option<Vec<u8>>,
        counter: usize,
    ) -> Result<Vec<u8>, JsValue> {
        if self.ciphertext.len() == 0 {
            return Err(JsValue::from("Missing ciphertext"));
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            self.header.counters[counter].get_to_sign(&self.ciphertext, &aead, &self.ph_bstr)
        }
    }
    pub fn get_to_sign(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut CoseAgent,
    ) -> Result<Vec<u8>, JsValue> {
        if self.ciphertext.len() == 0 {
            return Err(JsValue::from("Missing ciphertext"));
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.get_to_sign(&self.ciphertext, &aead, &self.ph_bstr)
        }
    }

    pub fn counters_verify(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: usize,
    ) -> Result<(), JsValue> {
        if self.ciphertext.len() == 0 {
            return Err(JsValue::from("Missing ciphertext"));
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            if self.header.counters[counter].verify(&self.ciphertext, &aead, &self.ph_bstr)? {
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

    pub fn gen_ciphertext(&mut self, external_aad: Option<Vec<u8>>) -> Result<(), JsValue> {
        if self.payload.len() <= 0 {
            return Err(JsValue::from("Missing payload"));
        }
        self.ph_bstr = self.header.get_protected_bstr(true)?;
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        let alg = self.header.alg.ok_or(JsValue::from("Missing Alg"))?;
        if self.recipients.len() <= 0 {
            if !algs::ENCRYPT_ALGS.contains(&alg) {
                return Err(JsValue::from("Invalid alg"));
            } else if !self.enc {
                return Err(JsValue::from("Key doesn't support encryption"));
            } else {
                self.ciphertext = enc_struct::gen_cipher(
                    &self.key,
                    &alg,
                    self.header.iv.as_ref().ok_or(JsValue::from("Missing iv"))?,
                    &aead,
                    enc_struct::ENCRYPT0,
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
                    return Err(JsValue::from("DIRECT alg only supports 1 recipient"));
                }
                if !self.recipients[0].key_ops.contains(&keys::KEY_OPS_ENCRYPT) {
                    return Err(JsValue::from("Key doesn't support encryption"));
                } else {
                    self.ciphertext = self.recipients[0].enc(
                        &self.payload,
                        &aead,
                        &self.ph_bstr,
                        &alg,
                        self.header.iv.as_ref().ok_or(JsValue::from("Missing iv"))?,
                    )?;
                    return Ok(());
                }
            } else if algs::ECDH_H.contains(
                self.recipients[0]
                    .header
                    .alg
                    .as_ref()
                    .ok_or(JsValue::from("Missing Alg"))?,
            ) {
                if self.recipients.len() > 1 {
                    return Err(JsValue::from("Only one recipient allowed for ECDH_HKDF"));
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
                        return Err(JsValue::from("Only one recipient allowed for alg"));
                    }
                    cek = self.recipients[i].derive_key(&cek, cek.len(), true, &alg)?;
                }
            }
            self.ciphertext = enc_struct::gen_cipher(
                &cek,
                &alg,
                self.header.iv.as_ref().ok_or(JsValue::from("Missing iv"))?,
                &aead,
                enc_struct::ENCRYPT,
                &self.ph_bstr,
                &self.payload,
            )?;
            Ok(())
        }
    }

    pub fn encode(&mut self, ciphertext: bool) -> Result<(), JsValue> {
        if self.recipients.len() <= 0 {
            if self.ciphertext.len() <= 0 {
                return Err(JsValue::from("Missing ciphertext"));
            } else {
                let mut e = Encoder::new();
                e.tag(common::ENC0_TAG)?;
                e.array(SIZE);
                e.bytes(self.ph_bstr.as_slice());
                self.header.encode_unprotected(&mut e)?;
                if ciphertext {
                    e.bytes(self.ciphertext.as_slice());
                } else {
                    e.null();
                }
                self.bytes = e.encoded();
                self.header.labels_found = Vec::new();
                Ok(())
            }
        } else {
            let mut e = Encoder::new();
            e.tag(common::ENC_TAG)?;
            e.array(SIZE_N);
            e.bytes(self.ph_bstr.as_slice());
            self.header.encode_unprotected(&mut e)?;
            if ciphertext {
                e.bytes(self.ciphertext.as_slice());
            } else {
                e.null();
            }
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

    pub fn init_decoder(&mut self) -> Result<(), JsValue> {
        let input = self.bytes.clone();
        let mut d = Decoder::new(input);
        let mut tag: Option<u32> = None;

        match d.tag() {
            Ok(v) => {
                if !ENC_TAGS.contains(&v) {
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
                        return Err(JsValue::from("Invalid COSE structure"));
                    }
                }
                Err(_) => return Err(JsValue::from("Invalid COSE structure")),
            },
        }
        if self.ph_bstr.len() > 0 {
            self.header.decode_protected_bstr(self.ph_bstr.clone())?;
        }
        self.header.decode_unprotected(&mut d, false)?;
        self.header.labels_found = Vec::new();

        if self.header.alg.ok_or(JsValue::from("Missing Alg"))? == algs::DIRECT
            && self.ph_bstr.len() > 0
        {
            return Err(JsValue::from("Invalid COSE Structure"));
        } else if algs::A_KW.contains(
            self.header
                .alg
                .as_ref()
                .ok_or(JsValue::from("Missing Alg"))?,
        ) && self.ph_bstr.len() > 0
        {
            return Err(JsValue::from("Invalid COSE Structure"));
        }
        self.ciphertext = d.bytes()?.to_vec();
        if self.ciphertext.len() <= 0 {
            return Err(JsValue::from("Missing ciphertext"));
        }

        let mut r_len = 0;
        let is_enc0 = match d.array() {
            Ok(v) => {
                r_len = v;
                false
            }
            Err(_) => true,
        };

        if !is_enc0 && (tag == None || tag.unwrap() == common::ENC_TAG) {
            let mut recipient: CoseAgent;
            for _ in 0..r_len {
                recipient = CoseAgent::new();
                recipient.context = enc_struct::ENCRYPT_RECIPIENT.to_string();
                d.array()?;
                match d.bytes() {
                    Ok(value) => recipient.ph_bstr = value,
                    Err(_) => match d.object() {
                        Ok(v) => {
                            if v == 0 {
                                recipient.ph_bstr = Vec::new();
                            } else {
                                return Err(JsValue::from("Invalid COSE structure"));
                            }
                        }
                        Err(_) => return Err(JsValue::from("Invalid COSE structure")),
                    },
                }
                recipient.decode(&mut d)?;
                self.recipients.push(recipient);
            }
        } else if is_enc0 && (tag == None || tag.unwrap() == common::ENC0_TAG) {
            if self.ciphertext.len() <= 0 {
                return Err(JsValue::from("Missing ciphertext"));
            }
        }
        Ok(())
    }

    pub fn decode(
        &mut self,
        external_aad: Option<Vec<u8>>,
        recipient: Option<usize>,
    ) -> Result<Vec<u8>, JsValue> {
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        let alg = self.header.alg.ok_or(JsValue::from("Missing Alg"))?;
        if self.recipients.len() <= 0 {
            if !self.dec {
                return Err(JsValue::from("Key doesn't support decrypt"));
            } else {
                Ok(enc_struct::dec_cipher(
                    &self.key,
                    &alg,
                    self.header.iv.as_ref().ok_or(JsValue::from("Missing iv"))?,
                    &aead,
                    enc_struct::ENCRYPT0,
                    &self.ph_bstr,
                    &self.ciphertext,
                )?)
            }
        } else if recipient != None {
            let size = algs::get_cek_size(&alg)?;
            let index = recipient.ok_or(JsValue::from("Missing recipient"))?;
            let cek;
            if algs::DIRECT
                == self.recipients[index]
                    .header
                    .alg
                    .ok_or(JsValue::from("Missing Alg"))?
            {
                if !self.recipients[index]
                    .key_ops
                    .contains(&keys::KEY_OPS_DECRYPT)
                {
                    return Err(JsValue::from("Key doesn't support decrypt"));
                } else {
                    return Ok(self.recipients[index].dec(
                        &self.ciphertext,
                        &aead,
                        &self.ph_bstr,
                        &alg,
                        self.header.iv.as_ref().ok_or(JsValue::from("Missing iv"))?,
                    )?);
                }
            } else {
                let payload = self.recipients[index].payload.clone();
                cek = self.recipients[index].derive_key(&payload, size, false, &alg)?;
            }
            Ok(enc_struct::dec_cipher(
                &cek,
                &alg,
                self.header.iv.as_ref().ok_or(JsValue::from("Missing iv"))?,
                &aead,
                enc_struct::ENCRYPT,
                &self.ph_bstr,
                &self.ciphertext,
            )?)
        } else {
            return Err(JsValue::from("Missing recipient"));
        }
    }
}
