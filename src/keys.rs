use crate::algs;
use crate::cbor::{Decoder, Encoder};
use crate::common;
use wasm_bindgen::prelude::*;

const DER_S: [u8; 16] = [48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32];
const DER_P: [u8; 12] = [48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0];

pub(crate) const ECDH_KTY: [i32; 2] = [OKP, EC2];
pub(crate) const D: i32 = -4;
pub(crate) const Y: i32 = -3;
pub(crate) const X: i32 = -2;
pub(crate) const CRV_K: i32 = -1;
pub(crate) const KTY: i32 = 1;
pub(crate) const KID: i32 = 2;
pub(crate) const ALG: i32 = 3;
pub(crate) const KEY_OPS: i32 = 4;
pub(crate) const BASE_IV: i32 = 5;

pub(crate) const OKP: i32 = 1;
pub(crate) const EC2: i32 = 2;
pub(crate) const SYMMETRIC: i32 = 4;
pub(crate) const RESERVED: i32 = 0;
pub(crate) const KTY_ALL: [i32; 4] = [RESERVED, OKP, EC2, SYMMETRIC];
pub(crate) const KTY_NAMES: [&str; 4] = ["Reserved", "OKP", "EC2", "Symmetric"];

pub(crate) const KEY_OPS_SIGN: i32 = 1;
pub(crate) const KEY_OPS_VERIFY: i32 = 2;
pub(crate) const KEY_OPS_ENCRYPT: i32 = 3;
pub(crate) const KEY_OPS_DECRYPT: i32 = 4;
pub(crate) const KEY_OPS_WRAP: i32 = 5;
pub(crate) const KEY_OPS_UNWRAP: i32 = 6;
pub(crate) const KEY_OPS_DERIVE: i32 = 7;
pub(crate) const KEY_OPS_DERIVE_BITS: i32 = 8;
pub(crate) const KEY_OPS_MAC: i32 = 9;
pub(crate) const KEY_OPS_MAC_VERIFY: i32 = 10;
pub(crate) const KEY_OPS_ALL: [i32; 10] = [
    KEY_OPS_SIGN,
    KEY_OPS_VERIFY,
    KEY_OPS_ENCRYPT,
    KEY_OPS_DECRYPT,
    KEY_OPS_WRAP,
    KEY_OPS_UNWRAP,
    KEY_OPS_DERIVE,
    KEY_OPS_DERIVE_BITS,
    KEY_OPS_MAC,
    KEY_OPS_MAC_VERIFY,
];
pub(crate) const KEY_OPS_NAMES: [&str; 10] = [
    "sign",
    "verify",
    "encrypt",
    "decrypt",
    "wrap key",
    "unwrap key",
    "derive key",
    "derive bits",
    "MAC create",
    "MAC verify",
];

pub(crate) const P_256: i32 = 1;
pub(crate) const P_384: i32 = 2;
pub(crate) const P_521: i32 = 3;
pub(crate) const X25519: i32 = 4;
pub(crate) const X448: i32 = 5;
pub(crate) const ED25519: i32 = 6;
pub(crate) const ED448: i32 = 7;
pub(crate) const CURVES_ALL: [i32; 7] = [P_256, P_384, P_521, X25519, X448, ED25519, ED448];
const EC2_CRVS: [i32; 3] = [P_256, P_384, P_521];
pub(crate) const CURVES_NAMES: [&str; 7] = [
    "P-256", "P-384", "P-521", "X25519", "X448", "Ed25519", "Ed448",
];

#[derive(Clone)]
#[wasm_bindgen]
pub struct CoseKey {
    pub(crate) bytes: Vec<u8>,
    used: Vec<i32>,
    pub(crate) kty: Option<i32>,
    pub(crate) base_iv: Option<Vec<u8>>,
    pub(crate) key_ops: Vec<i32>,
    pub(crate) alg: Option<i32>,
    pub(crate) x: Option<Vec<u8>>,
    pub(crate) y: Option<Vec<u8>>,
    pub(crate) d: Option<Vec<u8>>,
    pub(crate) k: Option<Vec<u8>>,
    pub(crate) kid: Option<Vec<u8>>,
    pub(crate) crv: Option<i32>,
}

#[wasm_bindgen]
impl CoseKey {
    #[wasm_bindgen(constructor)]
    pub fn new() -> CoseKey {
        CoseKey {
            bytes: Vec::new(),
            used: Vec::new(),
            key_ops: Vec::new(),
            base_iv: None,
            kty: None,
            alg: None,
            x: None,
            y: None,
            d: None,
            k: None,
            kid: None,
            crv: None,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn kty(&self) -> Option<i32> {
        self.kty.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn base_iv(&self) -> Option<Vec<u8>> {
        self.base_iv.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn key_ops(&self) -> Vec<i32> {
        self.key_ops.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn alg(&self) -> Option<i32> {
        self.alg.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn x(&self) -> Option<Vec<u8>> {
        self.x.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn y(&self) -> Option<Vec<u8>> {
        self.y.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn d(&self) -> Option<Vec<u8>> {
        self.d.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn k(&self) -> Option<Vec<u8>> {
        self.k.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn kid(&self) -> Option<Vec<u8>> {
        self.kid.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn crv(&self) -> Option<i32> {
        self.crv.clone()
    }

    pub fn set_bytes(&mut self, bytes: Vec<u8>) {
        self.bytes = bytes;
    }

    fn reg_label(&mut self, label: i32) {
        self.used.retain(|&x| x != label);
        self.used.push(label);
    }

    pub(crate) fn remove_label(&mut self, label: i32) {
        self.used.retain(|&x| x != label);
    }

    pub fn set_kty(&mut self, kty: i32) {
        self.reg_label(KTY);
        self.kty = Some(kty);
    }

    pub fn set_kid(&mut self, kid: Vec<u8>) {
        self.reg_label(KID);
        self.kid = Some(kid);
    }

    pub fn set_alg(&mut self, alg: i32) {
        self.reg_label(ALG);
        self.alg = Some(alg);
    }

    pub fn set_key_ops(&mut self, key_ops: Vec<i32>) {
        self.reg_label(KEY_OPS);
        self.key_ops = key_ops;
    }

    pub fn set_base_iv(&mut self, base_iv: Vec<u8>) {
        self.reg_label(BASE_IV);
        self.base_iv = Some(base_iv);
    }

    pub fn set_crv(&mut self, crv: i32) {
        self.reg_label(CRV_K);
        self.crv = Some(crv);
    }

    pub fn set_x(&mut self, x: Vec<u8>) {
        self.reg_label(X);
        self.x = Some(x);
    }

    pub fn set_y(&mut self, y: Vec<u8>) {
        self.reg_label(Y);
        self.y = Some(y);
    }

    pub fn set_d(&mut self, d: Vec<u8>) {
        self.reg_label(D);
        self.d = Some(d);
    }

    pub fn set_k(&mut self, k: Vec<u8>) {
        self.reg_label(CRV_K);
        self.k = Some(k);
    }

    pub(crate) fn verify_curve(&self) -> Result<(), JsValue> {
        let kty = self.kty.ok_or(JsValue::from("KTY missing"))?;
        if kty == SYMMETRIC {
            return Ok(());
        }
        let crv = self.crv.ok_or(JsValue::from("Curve missing"))?;
        if kty == OKP && ED25519 == crv {
            Ok(())
        } else if kty == EC2 && EC2_CRVS.contains(&crv) {
            Ok(())
        } else {
            Err(JsValue::from("Invalid Curve"))
        }
    }

    pub(crate) fn verify_kty(&self) -> Result<(), JsValue> {
        let kty = self.kty.ok_or(JsValue::from("Missing KTY"))?;
        let alg = self.alg.ok_or(JsValue::from("Missing Algorithm"))?;
        if kty == OKP && algs::OKP_ALGS.contains(&alg) {
        } else if kty == EC2 && algs::EC2_ALGS.contains(&alg) {
        } else if kty == SYMMETRIC && algs::SYMMETRIC_ALGS.contains(&alg) {
        } else {
            return Err(JsValue::from("Invalid KTY"));
        }
        self.verify_curve()?;
        Ok(())
    }

    pub fn encode(&mut self) -> Result<(), JsValue> {
        let mut e = Encoder::new();
        if self.alg != None {
            self.verify_kty()?;
        } else {
            self.verify_curve()?;
        }
        self.encode_key(&mut e)?;
        self.bytes = e.encoded();
        Ok(())
    }
    pub(crate) fn encode_key(&self, e: &mut Encoder) -> Result<(), JsValue> {
        let kty = self.kty.ok_or(JsValue::from("Missing KTY"))?;
        let key_ops_len = self.key_ops.len();
        if key_ops_len > 0 {
            if kty == EC2 || kty == OKP {
                if self.key_ops.contains(&KEY_OPS_VERIFY)
                    || self.key_ops.contains(&KEY_OPS_DERIVE)
                    || self.key_ops.contains(&KEY_OPS_DERIVE_BITS)
                {
                    if self.x == None {
                        return Err(JsValue::from("Missing X parameter"));
                    } else if self.crv == None {
                        return Err(JsValue::from("Missing Curve"));
                    }
                }
                if self.key_ops.contains(&KEY_OPS_SIGN) {
                    if self.d == None {
                        return Err(JsValue::from("Missing D parameter"));
                    } else if self.crv == None {
                        return Err(JsValue::from("Missing Curve"));
                    }
                }
            } else if kty == SYMMETRIC {
                if self.key_ops.contains(&KEY_OPS_ENCRYPT)
                    || self.key_ops.contains(&KEY_OPS_MAC_VERIFY)
                    || self.key_ops.contains(&KEY_OPS_MAC)
                    || self.key_ops.contains(&KEY_OPS_DECRYPT)
                    || self.key_ops.contains(&KEY_OPS_UNWRAP)
                    || self.key_ops.contains(&KEY_OPS_WRAP)
                {
                    if self.x != None {
                        return Err(JsValue::from("Invalid X value"));
                    } else if self.y != None {
                        return Err(JsValue::from("Invalid Y value"));
                    } else if self.d != None {
                        return Err(JsValue::from("Invalid D value"));
                    }
                    if self.k == None {
                        return Err(JsValue::from("Missing K value"));
                    }
                }
            }
        }
        e.object(self.used.len());
        for i in &self.used {
            e.signed(*i);

            if *i == KTY {
                e.signed(kty);
            } else if *i == KEY_OPS {
                e.array(self.key_ops.len());
                for x in &self.key_ops {
                    e.signed(*x);
                }
            } else if *i == CRV_K {
                if self.crv != None {
                    e.signed(self.crv.ok_or(JsValue::from("Missing Curve"))?)
                } else {
                    e.bytes(
                        &self
                            .k
                            .as_ref()
                            .ok_or(JsValue::from("Missing K parameter"))?,
                    )
                }
            } else if *i == KID {
                e.bytes(&self.kid.as_ref().ok_or(JsValue::from("Missing KID"))?)
            } else if *i == ALG {
                e.signed(self.alg.ok_or(JsValue::from("Missing Algorithm"))?)
            } else if *i == BASE_IV {
                e.bytes(
                    &self
                        .base_iv
                        .as_ref()
                        .ok_or(JsValue::from("Missing Base IV"))?,
                )
            } else if *i == X {
                e.bytes(
                    &self
                        .x
                        .as_ref()
                        .ok_or(JsValue::from("Missing X parameter"))?,
                )
            } else if *i == Y {
                e.bytes(
                    &self
                        .y
                        .as_ref()
                        .ok_or(JsValue::from("Missing Y parameter"))?,
                )
            } else if *i == D {
                e.bytes(
                    &self
                        .d
                        .as_ref()
                        .ok_or(JsValue::from("Missing D parameter"))?,
                )
            } else {
                return Err(("Duplicate Label ".to_owned() + &i.to_string()).into());
            }
        }
        Ok(())
    }

    pub fn decode(&mut self) -> Result<(), JsValue> {
        let input = self.bytes.clone();
        let mut d = Decoder::new(input);
        self.decode_key(&mut d)?;
        if self.alg != None {
            self.verify_kty()?;
        } else {
            self.verify_curve()?;
        }
        Ok(())
    }

    pub(crate) fn decode_key(&mut self, d: &mut Decoder) -> Result<(), JsValue> {
        let mut label: i32;
        let mut labels_found = Vec::new();
        self.used = Vec::new();
        for _ in 0..d.object()? {
            label = d.signed()?;
            if !labels_found.contains(&label) {
                labels_found.push(label);
            } else {
                return Err(("Duplicate Label ".to_owned() + &label.to_string()).into());
            }
            if label == KTY {
                self.kty = match d.text() {
                    Ok(value) => Some(common::get_kty_id(value)?),
                    Err(_) => match d.signed() {
                        Ok(v) => Some(v),
                        Err(_) => {
                            return Err(JsValue::from("Invalid COSE Structure"));
                        }
                    },
                };
                self.used.push(label);
            } else if label == ALG {
                self.alg = match d.text() {
                    Ok(value) => Some(common::get_alg_id(value)?),
                    Err(_) => match d.signed() {
                        Ok(v) => Some(v),
                        Err(_) => {
                            return Err(JsValue::from("Invalid COSE Structure"));
                        }
                    },
                };
                self.used.push(label);
            } else if label == KID {
                self.kid = Some(d.bytes()?);
                self.used.push(label);
            } else if label == KEY_OPS {
                let mut key_ops = Vec::new();
                for _i in 0..d.array()? {
                    match d.text() {
                        Ok(value) => {
                            key_ops.push(common::get_key_op_id(value)?);
                        }
                        Err(_) => match d.signed() {
                            Ok(v) => {
                                key_ops.push(v);
                            }
                            Err(_) => {
                                return Err(JsValue::from("Invalid COSE Structure"));
                            }
                        },
                    }
                }
                self.key_ops = key_ops;
                self.used.push(label);
            } else if label == BASE_IV {
                self.base_iv = Some(d.bytes()?);
                self.used.push(label);
            } else if label == CRV_K {
                match d.bytes() {
                    Ok(v) => self.k = Some(v),
                    Err(_) => {
                        self.crv = match d.text() {
                            Ok(value) => Some(common::get_crv_id(value)?),
                            Err(_) => match d.signed() {
                                Ok(v) => Some(v),
                                Err(_) => {
                                    return Err(JsValue::from("Invalid COSE Structure"));
                                }
                            },
                        };
                    }
                };
                self.used.push(label);
            } else if label == X {
                self.x = Some(d.bytes()?);
                self.used.push(label);
            } else if label == Y {
                self.y = match d.bytes() {
                    Ok(value) => {
                        self.used.push(label);
                        Some(value)
                    }
                    Err(err) => {
                        if err == 244 || err == 245 {
                            d.skip();
                            None
                        } else {
                            return Err(JsValue::from("Invalid Y parameter"));
                        }
                    }
                };
            } else if label == D {
                self.d = Some(d.bytes()?);
                self.used.push(label);
            } else {
                return Err(JsValue::from(
                    "Invalid Label ".to_owned() + &label.to_string(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn get_s_key(&self) -> Result<Vec<u8>, JsValue> {
        let mut s_key = Vec::new();
        let alg = self.alg.ok_or(JsValue::from("Missing Algorithm"))?;
        if algs::SIGNING_ALGS.contains(&alg) || algs::ECDH_ALGS.contains(&alg) {
            let mut d = self
                .d
                .as_ref()
                .ok_or(JsValue::from("Missing D parameter"))?
                .to_vec();
            if d.len() <= 0 {
                return Err(JsValue::from("Missing D parameter"));
            }
            if algs::EDDSA == alg {
                s_key = DER_S.to_vec();
                s_key.append(&mut d);
            } else {
                s_key = d;
            }
        } else if algs::MAC_ALGS.contains(&alg)
            || algs::ENCRYPT_ALGS.contains(&alg)
            || algs::KEY_DISTRIBUTION_ALGS.contains(&alg)
        {
            let k = self
                .k
                .as_ref()
                .ok_or(JsValue::from("Missing K parameter"))?
                .to_vec();
            if k.len() <= 0 {
                return Err(JsValue::from("Missing K parameter"));
            }
            s_key = k;
        }
        Ok(s_key)
    }
    pub(crate) fn get_pub_key(&self, alg: i32) -> Result<Vec<u8>, JsValue> {
        let mut pub_key: Vec<u8>;
        if algs::SIGNING_ALGS.contains(&alg) || algs::ECDH_ALGS.contains(&alg) {
            let mut x = self
                .x
                .as_ref()
                .ok_or(JsValue::from("Missing X parameter"))?
                .to_vec();
            if x.len() <= 0 {
                return Err(JsValue::from("Missing X parameter"));
            }
            if algs::EDDSA == alg {
                pub_key = DER_P.to_vec();
                pub_key.append(&mut x);
            } else {
                if self.y == None {
                    pub_key = vec![3];
                    pub_key.append(&mut x);
                } else {
                    let mut y = self
                        .y
                        .as_ref()
                        .ok_or(JsValue::from("Missing Y parameter"))?
                        .to_vec();
                    pub_key = vec![4];
                    pub_key.append(&mut x);
                    pub_key.append(&mut y);
                }
            }
        } else {
            return Err(JsValue::from("Invalid Algorithm"));
        }
        Ok(pub_key)
    }
}

#[wasm_bindgen]
pub struct CoseKeySet {
    pub(crate) cose_keys: Vec<CoseKey>,
    pub(crate) bytes: Vec<u8>,
}

#[wasm_bindgen]
impl CoseKeySet {
    #[wasm_bindgen(constructor)]
    pub fn new() -> CoseKeySet {
        CoseKeySet {
            cose_keys: Vec::new(),
            bytes: Vec::new(),
        }
    }

    pub fn add_key(&mut self, key: CoseKey) {
        self.cose_keys.push(key);
    }

    pub fn encode(&mut self) -> Result<(), JsValue> {
        let mut e = Encoder::new();
        let len = self.cose_keys.len();
        if len > 0 {
            e.array(len);
            for i in 0..len {
                self.cose_keys[i].encode_key(&mut e)?;
            }
            self.bytes = e.encoded();
            Ok(())
        } else {
            return Err(JsValue::from("Empty Key Set"));
        }
    }

    pub fn decode(&mut self) -> Result<(), JsValue> {
        let input = self.bytes.clone();
        let mut d = Decoder::new(input);
        let len = d.array()?;
        if len > 0 {
            for _ in 0..len {
                let mut cose_key = CoseKey::new();
                match cose_key.decode_key(&mut d) {
                    Ok(_v) => self.cose_keys.push(cose_key),
                    Err(_e) => (),
                }
            }
            Ok(())
        } else {
            return Err(JsValue::from("Empty Key Set"));
        }
    }

    pub fn get_key(&self, kid: Vec<u8>) -> Result<CoseKey, JsValue> {
        for i in 0..self.cose_keys.len() {
            if self.cose_keys[i]
                .kid
                .as_ref()
                .ok_or(JsValue::from("Missing KID"))?
                == &kid
            {
                return Ok(self.cose_keys[i].clone());
            }
        }
        return Err(JsValue::from("Key not found"));
    }
}
