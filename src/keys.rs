use crate::algs;
use crate::cbor::{Decoder, Encoder, CBOR_FALSE, CBOR_TRUE};
use crate::headers;
use rsa::pkcs8::EncodePublicKey;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use wasm_bindgen::prelude::*;

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

pub(crate) const N: i32 = -1;
pub(crate) const E: i32 = -2;
pub(crate) const RSA_D: i32 = -3;
pub(crate) const P: i32 = -4;
pub(crate) const Q: i32 = -5;
pub(crate) const DP: i32 = -6;
pub(crate) const DQ: i32 = -7;
pub(crate) const QINV: i32 = -8;
pub(crate) const OTHER: i32 = -9;
pub(crate) const RI: i32 = -10;
pub(crate) const DI: i32 = -11;
pub(crate) const TI: i32 = -12;

pub(crate) const OKP: i32 = 1;
pub(crate) const EC2: i32 = 2;
pub(crate) const RSA: i32 = 3;
pub(crate) const SYMMETRIC: i32 = 4;
pub(crate) const RESERVED: i32 = 0;
pub(crate) const KTY_ALL: [i32; 5] = [RESERVED, OKP, EC2, RSA, SYMMETRIC];
pub(crate) const KTY_NAMES: [&str; 5] = ["Reserved", "OKP", "EC2", "RSA", "Symmetric"];

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
pub const SECP256K1: i32 = 8;
pub(crate) const P_384: i32 = 2;
pub(crate) const P_521: i32 = 3;
pub(crate) const X25519: i32 = 4;
pub(crate) const X448: i32 = 5;
pub(crate) const ED25519: i32 = 6;
pub(crate) const ED448: i32 = 7;
pub(crate) const CURVES_ALL: [i32; 8] =
    [P_256, P_384, P_521, X25519, X448, ED25519, ED448, SECP256K1];
const EC2_CRVS: [i32; 3] = [P_256, P_384, P_521];
pub(crate) const CURVES_NAMES: [&str; 8] = [
    "P-256",
    "P-384",
    "P-521",
    "X25519",
    "X448",
    "Ed25519",
    "Ed448",
    "secp256k1",
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
    pub(crate) n: Option<Vec<u8>>,
    pub(crate) e: Option<Vec<u8>>,
    pub(crate) rsa_d: Option<Vec<u8>>,
    pub(crate) p: Option<Vec<u8>>,
    pub(crate) q: Option<Vec<u8>>,
    pub(crate) dp: Option<Vec<u8>>,
    pub(crate) dq: Option<Vec<u8>>,
    pub(crate) qinv: Option<Vec<u8>>,
    pub(crate) other: Option<Vec<Vec<u8>>>,
    pub(crate) ri: Option<Vec<u8>>,
    pub(crate) di: Option<Vec<u8>>,
    pub(crate) ti: Option<Vec<u8>>,
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
            n: None,
            e: None,
            rsa_d: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            qinv: None,
            other: None,
            ri: None,
            di: None,
            ti: None,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_bytes(&mut self, bytes: Vec<u8>) {
        self.bytes = bytes;
    }
    #[wasm_bindgen(getter)]
    pub fn kty(&self) -> Option<i32> {
        self.kty.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_kty(&mut self, kty: Option<i32>) {
        self.reg_label(KTY);
        self.kty = kty;
    }
    #[wasm_bindgen(getter)]
    pub fn base_iv(&self) -> Option<Vec<u8>> {
        self.base_iv.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_base_iv(&mut self, base_iv: Option<Vec<u8>>) {
        self.reg_label(BASE_IV);
        self.base_iv = base_iv;
    }
    #[wasm_bindgen(getter)]
    pub fn key_ops(&self) -> Vec<i32> {
        self.key_ops.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_key_ops(&mut self, key_ops: Vec<i32>) {
        self.reg_label(KEY_OPS);
        self.key_ops = key_ops;
    }
    #[wasm_bindgen(getter)]
    pub fn alg(&self) -> Option<i32> {
        self.alg.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_alg(&mut self, alg: Option<i32>) {
        self.reg_label(ALG);
        self.alg = alg;
    }
    #[wasm_bindgen(getter)]
    pub fn x(&self) -> Option<Vec<u8>> {
        self.x.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_x(&mut self, x: Option<Vec<u8>>) {
        self.reg_label(X);
        self.x = x;
    }
    #[wasm_bindgen(getter)]
    pub fn y(&self) -> Option<Vec<u8>> {
        self.y.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_y(&mut self, y: Option<Vec<u8>>) {
        self.reg_label(Y);
        self.y = y;
    }
    #[wasm_bindgen(getter)]
    pub fn d(&self) -> Option<Vec<u8>> {
        self.d.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_d(&mut self, d: Option<Vec<u8>>) {
        self.reg_label(D);
        self.d = d;
    }
    #[wasm_bindgen(getter)]
    pub fn k(&self) -> Option<Vec<u8>> {
        self.k.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_k(&mut self, k: Option<Vec<u8>>) {
        self.reg_label(CRV_K);
        self.k = k;
    }
    #[wasm_bindgen(getter)]
    pub fn kid(&self) -> Option<Vec<u8>> {
        self.kid.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_kid(&mut self, kid: Option<Vec<u8>>) {
        self.reg_label(KID);
        self.kid = kid;
    }
    #[wasm_bindgen(getter)]
    pub fn crv(&self) -> Option<i32> {
        self.crv.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_crv(&mut self, crv: Option<i32>) {
        self.reg_label(CRV_K);
        self.crv = crv;
    }
    #[wasm_bindgen(getter)]
    pub fn n(&self) -> Option<Vec<u8>> {
        self.n.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_n(&mut self, n: Option<Vec<u8>>) {
        self.reg_label(N);
        self.n = n;
    }
    #[wasm_bindgen(getter)]
    pub fn e(&self) -> Option<Vec<u8>> {
        self.e.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_e(&mut self, e: Option<Vec<u8>>) {
        self.reg_label(E);
        self.e = e;
    }
    #[wasm_bindgen(getter)]
    pub fn rsa_d(&self) -> Option<Vec<u8>> {
        self.rsa_d.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_rsa_d(&mut self, rsa_d: Option<Vec<u8>>) {
        self.reg_label(RSA_D);
        self.rsa_d = rsa_d;
    }
    #[wasm_bindgen(getter)]
    pub fn p(&self) -> Option<Vec<u8>> {
        self.p.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_p(&mut self, p: Option<Vec<u8>>) {
        self.reg_label(P);
        self.p = p;
    }
    #[wasm_bindgen(getter)]
    pub fn q(&self) -> Option<Vec<u8>> {
        self.q.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_q(&mut self, q: Option<Vec<u8>>) {
        self.reg_label(Q);
        self.q = q;
    }
    #[wasm_bindgen(getter)]
    pub fn dp(&self) -> Option<Vec<u8>> {
        self.dp.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_dp(&mut self, dp: Option<Vec<u8>>) {
        self.reg_label(DP);
        self.dp = dp;
    }
    #[wasm_bindgen(getter)]
    pub fn dq(&self) -> Option<Vec<u8>> {
        self.dq.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_dq(&mut self, dq: Option<Vec<u8>>) {
        self.reg_label(DQ);
        self.dq = dq;
    }
    #[wasm_bindgen(getter)]
    pub fn qinv(&self) -> Option<Vec<u8>> {
        self.qinv.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_qinv(&mut self, qinv: Option<Vec<u8>>) {
        self.reg_label(QINV);
        self.qinv = qinv;
    }
    #[wasm_bindgen(getter)]
    pub fn ri(&self) -> Option<Vec<u8>> {
        self.ri.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_ri(&mut self, ri: Option<Vec<u8>>) {
        self.reg_label(RI);
        self.ri = ri;
    }
    #[wasm_bindgen(getter)]
    pub fn di(&self) -> Option<Vec<u8>> {
        self.di.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_di(&mut self, di: Option<Vec<u8>>) {
        self.reg_label(DI);
        self.di = di;
    }
    #[wasm_bindgen(getter)]
    pub fn ti(&self) -> Option<Vec<u8>> {
        self.ti.clone()
    }
    #[wasm_bindgen(setter)]
    pub fn set_ti(&mut self, ti: Option<Vec<u8>>) {
        self.reg_label(TI);
        self.ti = ti;
    }

    fn reg_label(&mut self, label: i32) {
        self.used.retain(|&x| x != label);
        self.used.push(label);
    }

    pub(crate) fn remove_label(&mut self, label: i32) {
        self.used.retain(|&x| x != label);
    }

    pub(crate) fn verify_curve(&self) -> Result<(), JsValue> {
        let kty = self.kty.ok_or(JsValue::from("MissingKTY"))?;
        if kty == SYMMETRIC || kty == RSA {
            return Ok(());
        }
        let crv = self.crv.ok_or(JsValue::from("MissingCRV"))?;

        if kty == OKP && [ED25519, ED448, X25519, X448].contains(&crv) {
            Ok(())
        } else if kty == EC2 && EC2_CRVS.contains(&crv) {
            Ok(())
        } else if self.alg.ok_or(JsValue::from("MissingAlg"))? == algs::ES256K && crv == SECP256K1 {
            Ok(())
        } else {
            Err(JsValue::from("InvalidCRV"))
        }
    }

    pub(crate) fn verify_kty(&self) -> Result<(), JsValue> {
        if !KTY_ALL.contains(&self.kty.ok_or(JsValue::from("MissingKTY"))?) {
            return Err(JsValue::from("InvalidKTY"));
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
            } else if *i == N {
                e.bytes(&self.n.as_ref().ok_or(JsValue::from("MissingN"))?)
            } else if *i == E {
                e.bytes(&self.e.as_ref().ok_or(JsValue::from("MissingE"))?)
            } else if *i == RSA_D {
                e.bytes(&self.rsa_d.as_ref().ok_or(JsValue::from("MissingRsaD"))?)
            } else if *i == P {
                e.bytes(&self.p.as_ref().ok_or(JsValue::from("MissingP"))?)
            } else if *i == Q {
                e.bytes(&self.q.as_ref().ok_or(JsValue::from("MissingQ"))?)
            } else if *i == DP {
                e.bytes(&self.dp.as_ref().ok_or(JsValue::from("MissingDP"))?)
            } else if *i == DQ {
                e.bytes(&self.dq.as_ref().ok_or(JsValue::from("MissingDQ"))?)
            } else if *i == QINV {
                e.bytes(&self.qinv.as_ref().ok_or(JsValue::from("MissingQINV"))?);
            } else if *i == OTHER {
                let other = self.other.as_ref().ok_or(JsValue::from("MissingOther"))?;
                e.array(other.len());
                for i in other {
                    e.bytes(i);
                }
            } else if *i == RI {
                e.bytes(&self.ri.as_ref().ok_or(JsValue::from("MissingRI"))?);
            } else if *i == DI {
                e.bytes(&self.di.as_ref().ok_or(JsValue::from("MissingDI"))?);
            } else if *i == TI {
                e.bytes(&self.ti.as_ref().ok_or(JsValue::from("MissingTI"))?);
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
                    Ok(value) => Some(headers::get_kty_id(value)?),
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
                    Ok(value) => Some(headers::get_alg_id(value)?),
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
                            key_ops.push(headers::get_key_op_id(value)?);
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
                            Ok(value) => Some(headers::get_crv_id(value)?),
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
                        if err == CBOR_FALSE || err == CBOR_TRUE {
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
            } else if label == N {
                self.n = Some(d.bytes()?);
                self.used.push(label);
            } else if label == E {
                self.e = Some(d.bytes()?);
                self.used.push(label);
            } else if label == RSA_D {
                self.rsa_d = Some(d.bytes()?);
                self.used.push(label);
            } else if label == P {
                self.p = Some(d.bytes()?);
                self.used.push(label);
            } else if label == Q {
                self.q = Some(d.bytes()?);
                self.used.push(label);
            } else if label == DP {
                self.dp = Some(d.bytes()?);
                self.used.push(label);
            } else if label == DQ {
                self.dq = Some(d.bytes()?);
                self.used.push(label);
            } else if label == QINV {
                self.qinv = Some(d.bytes()?);
                self.used.push(label);
            } else if label == OTHER {
                let mut other = Vec::new();
                for _ in 0..d.array()? {
                    other.push(d.bytes()?);
                }
                self.other = Some(other);
                self.used.push(label);
            } else if label == RI {
                self.ri = Some(d.bytes()?);
                self.used.push(label);
            } else if label == DI {
                self.di = Some(d.bytes()?);
                self.used.push(label);
            } else if label == TI {
                self.ti = Some(d.bytes()?);
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
        let kty = self.kty.ok_or(JsValue::from("MissingKTY"))?;
        if kty == EC2 || kty == OKP {
            let d = self
                .d
                .as_ref()
                .ok_or(JsValue::from("MissingD())?.to_vec"))?
                .clone();
            if d.len() <= 0 {
                return Err(JsValue::from("MissingD"));
            }
            Ok(d)
        } else if kty == RSA {
            use rsa::pkcs1::EncodeRsaPrivateKey;
            match RsaPrivateKey::from_components(
                BigUint::from_bytes_be(self.n.as_ref().ok_or(JsValue::from("Missing N"))?),
                BigUint::from_bytes_be(self.e.as_ref().ok_or(JsValue::from("Missing N"))?),
                BigUint::from_bytes_be(self.rsa_d.as_ref().ok_or(JsValue::from("Missing N"))?),
                vec![
                    BigUint::from_bytes_be(self.p.as_ref().ok_or(JsValue::from("Missing N"))?),
                    BigUint::from_bytes_be(self.q.as_ref().ok_or(JsValue::from("Missing N"))?),
                ],
            ) {
                Ok(v) => match v.to_pkcs1_der() {
                    Ok(v2) => {
                        return Ok(v2.to_bytes().to_vec());
                    }
                    Err(_) => {
                        return Err(JsValue::from("RSA Public Key error"));
                    }
                },
                Err(_) => {
                    return Err(JsValue::from("RSA Public Key error"));
                }
            };
        } else if kty == SYMMETRIC {
            let k = self
                .k
                .as_ref()
                .ok_or(JsValue::from("MissingK())?.to_vec"))?
                .clone();
            if k.len() <= 0 {
                return Err(JsValue::from("MissingK"));
            }
            Ok(k)
        } else {
            Err(JsValue::from("InvalidKTY"))
        }
    }
    pub(crate) fn get_pub_key(&self) -> Result<Vec<u8>, JsValue> {
        let kty = self.kty.ok_or(JsValue::from("MissingKTY"))?;
        if kty == EC2 || kty == OKP {
            let mut x = self
                .x
                .as_ref()
                .ok_or(JsValue::from("MissingX())?.to_vec"))?
                .clone();
            if x.len() <= 0 {
                return Err(JsValue::from("MissingX"));
            }
            let mut pub_key;
            if kty == EC2 {
                if self.y != None && self.y.as_ref().unwrap().len() > 0 {
                    let mut y = self.y.as_ref().unwrap().to_vec();
                    pub_key = vec![4];
                    pub_key.append(&mut x);
                    pub_key.append(&mut y);
                } else {
                    pub_key = vec![3];
                    pub_key.append(&mut x);
                }
            } else {
                pub_key = x;
            }
            Ok(pub_key)
        } else if kty == RSA {
            match RsaPublicKey::new(
                BigUint::from_bytes_be(self.n.as_ref().ok_or(JsValue::from("Missing N"))?),
                BigUint::from_bytes_be(self.e.as_ref().ok_or(JsValue::from("Missing N"))?),
            ) {
                Ok(v) => match v.to_public_key_der() {
                    Ok(v2) => {
                        return Ok(v2.to_vec());
                    }
                    Err(_) => {
                        return Err(JsValue::from("RSA Public Key error"));
                    }
                },
                Err(_) => {
                    return Err(JsValue::from("RSA Public Key error"));
                }
            };
        } else {
            Err(JsValue::from("InvalidKTY"))
        }
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
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_bytes(&mut self, bytes: Vec<u8>) {
        self.bytes = bytes;
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
