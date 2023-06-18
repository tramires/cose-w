use std::str;
use wasm_bindgen::prelude::JsValue;
const CBOR_MAX: u8 = 24;
pub(crate) const CBOR_NULL: u8 = 246;
const MAJOR_NEG: u8 = 32;
const MAJOR_NEG_U8: u8 = 56;
const MAJOR_O: u8 = 160;
const MAJOR_O_U8: u8 = 184;
const MAJOR_A: u8 = 128;
const MAJOR_A_U8: u8 = 152;
const MAJOR_T: u8 = 96;
const MAJOR_T_U8: u8 = 120;
const MAJOR_B: u8 = 64;
const MAJOR_B_U8: u8 = 88;
const MAJOR_TAG: u8 = 192;
const MAJOR_TAG_1: u8 = 198;
const MAJOR_TAG_2: u8 = 212;
const MAJOR_TAG_U8: u8 = 216;

pub(crate) struct Encoder {
    encoded: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Encoder {
        Encoder {
            encoded: Vec::new(),
        }
    }
    pub fn encode_major(&mut self, len: usize, major: u8) {
        let mut e_major: Vec<u8> = [].to_vec();
        if len <= u8::MAX.into() {
            e_major = (len as u8).to_be_bytes().to_vec();
            self.encoded.push(major);
        } else if len <= u16::MAX.into() {
            self.encoded.push(major + 1);
            e_major = (len as u16).to_be_bytes().to_vec();
        } else if len <= u32::MAX.try_into().unwrap() {
            self.encoded.push(major + 2);
            e_major = (len as u32).to_be_bytes().to_vec();
        } else if len <= u64::MAX.try_into().unwrap() {
            self.encoded.push(major + 3);
            e_major = (len as u64).to_be_bytes().to_vec();
        }
        self.encoded = [&self.encoded[..], &e_major].concat();
    }
    pub fn object(&mut self, len: usize) {
        if len < CBOR_MAX.into() {
            self.encoded.push(MAJOR_O + len as u8);
        } else {
            self.encode_major(len, MAJOR_O_U8);
        }
    }
    pub fn array(&mut self, len: usize) {
        if len < CBOR_MAX.into() {
            self.encoded.push(MAJOR_A + len as u8);
        } else {
            self.encode_major(len, MAJOR_A_U8);
        }
    }
    pub fn text(&mut self, v: &str) {
        let len = v.len();
        if len < CBOR_MAX.into() {
            self.encoded.push(MAJOR_T + len as u8);
            self.encoded = [&self.encoded[..], &v.as_bytes()].concat();
        } else {
            self.encode_major(len, MAJOR_T_U8);
            self.encoded = [&self.encoded[..], &v.as_bytes()].concat();
        }
    }
    pub fn bytes(&mut self, v: &[u8]) {
        let len = v.len();
        if len < CBOR_MAX.into() {
            self.encoded.push(MAJOR_B + len as u8);
            self.encoded = [&self.encoded[..], v].concat();
        } else {
            self.encode_major(len, MAJOR_B_U8);
            self.encoded = [&self.encoded[..], v].concat();
        }
    }
    pub fn unsigned(&mut self, v: u32) {
        if v < CBOR_MAX.into() {
            self.encoded.push(v.try_into().unwrap());
        } else {
            self.encode_major(v as usize, CBOR_MAX);
        }
    }
    pub fn signed(&mut self, v: i32) {
        if v >= 0 {
            self.unsigned(v as u32);
        } else {
            let val = v * -1;
            if val <= CBOR_MAX as i32 {
                self.encoded.push(val as u8 + MAJOR_NEG - 1);
            } else {
                self.encode_major(val as usize, MAJOR_NEG_U8);
            }
        }
    }
    pub fn tag(&mut self, v: u32) -> Result<(), JsValue> {
        let value = v + MAJOR_TAG as u32;
        if value >= MAJOR_TAG_1 as u32 && value <= MAJOR_TAG_2 as u32 {
            self.encoded.push(value as u8);
            Ok(())
        } else if value >= CBOR_MAX as u32 {
            self.encode_major(v as usize, MAJOR_TAG_U8);
            Ok(())
        } else {
            Err(JsValue::from("Invalid tag"))
        }
    }
    pub fn null(&mut self) {
        self.encoded.push(CBOR_NULL);
    }
    pub fn encoded(&self) -> Vec<u8> {
        self.encoded.clone()
    }
}

pub(crate) struct Decoder {
    encoded: Vec<u8>,
    index: usize,
}

impl Decoder {
    pub fn new(bytes: Vec<u8>) -> Decoder {
        Decoder {
            encoded: bytes,
            index: 0,
        }
    }
    pub fn decode_major(&mut self, major: u8) -> usize {
        let major_type = self.encoded[self.index] - major;
        let out: usize;
        self.index += 1;
        if major_type == 0 {
            out = u8::from_be_bytes([self.encoded[self.index]]) as usize;
            self.index += 1;
        } else if major_type == 1 {
            out = u16::from_be_bytes(self.encoded[self.index..self.index + 2].try_into().unwrap())
                as usize;
            self.index += 2;
        } else if major_type == 2 {
            out = u32::from_be_bytes(self.encoded[self.index..self.index + 4].try_into().unwrap())
                as usize;
            self.index += 4;
        } else {
            out = u64::from_be_bytes(self.encoded[self.index..self.index + 8].try_into().unwrap())
                as usize;
            self.index += 8;
        }
        out
    }
    pub fn object(&mut self) -> Result<usize, u8> {
        let len: usize;
        let first = self.encoded[self.index];
        if first >= MAJOR_O && first < MAJOR_O_U8 {
            len = (self.encoded[self.index] - MAJOR_O).try_into().unwrap();
            self.index += 1;
        } else if first >= MAJOR_O_U8 && first <= MAJOR_O_U8 + 3 {
            len = self.decode_major(MAJOR_O_U8);
        } else {
            return Err(first);
        }
        Ok(len)
    }
    pub fn array(&mut self) -> Result<usize, u8> {
        let len: usize;
        if self.index >= self.encoded.len() {
            return Err(0);
        }
        let first = self.encoded[self.index];
        if first >= MAJOR_A && first < MAJOR_A_U8 {
            len = (self.encoded[self.index] - MAJOR_A).try_into().unwrap();
            self.index += 1;
        } else if first >= MAJOR_A_U8 && first <= MAJOR_A_U8 + 3 {
            len = self.decode_major(MAJOR_A_U8);
        } else {
            return Err(first);
        }
        Ok(len)
    }
    pub fn text(&mut self) -> Result<&str, u8> {
        let v: &str;
        let first = self.encoded[self.index];
        if first >= MAJOR_T && first < MAJOR_T_U8 {
            self.index += 1;
            v = str::from_utf8(
                &self.encoded[self.index..(self.index + (first - MAJOR_T) as usize)],
            )
            .unwrap();
            self.index += (first - MAJOR_T) as usize;
        } else if first >= MAJOR_T_U8 && first <= MAJOR_T_U8 + 3 {
            let size = self.decode_major(MAJOR_T_U8);
            v = str::from_utf8(&self.encoded[self.index..(self.index + size)]).unwrap();
            self.index += size;
        } else {
            return Err(first);
        }
        Ok(v)
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>, u8> {
        let v: Vec<u8>;
        let first = self.encoded[self.index];
        if first >= MAJOR_B && first < MAJOR_B_U8 {
            self.index += 1;
            v = self.encoded[self.index..(self.index + (first - MAJOR_B) as usize)].to_vec();
            self.index += (first - MAJOR_B) as usize;
        } else if first >= MAJOR_B_U8 && first <= MAJOR_B_U8 + 3 {
            let size = self.decode_major(MAJOR_B_U8);
            v = self.encoded[self.index..(self.index + size)].to_vec();
            self.index += size;
        } else {
            return Err(first);
        }
        Ok(v)
    }
    pub fn unsigned(&mut self) -> Result<u32, u8> {
        let v: u32;
        let first = self.encoded[self.index];
        if first < CBOR_MAX {
            v = self.encoded[self.index] as u32;
            self.index += 1;
        } else if first >= CBOR_MAX && first <= CBOR_MAX + 3 {
            v = self.decode_major(CBOR_MAX) as u32;
        } else {
            return Err(first);
        }
        Ok(v)
    }

    pub fn signed(&mut self) -> Result<i32, u8> {
        let first = self.encoded[self.index];
        if first <= CBOR_MAX + 3 {
            Ok(self.unsigned().unwrap() as i32)
        } else {
            let v: i32;
            if first < MAJOR_NEG_U8 {
                v = self.encoded[self.index] as i32 - MAJOR_NEG as i32 + 1;
                self.index += 1;
            } else if first >= MAJOR_NEG_U8 && first <= MAJOR_NEG_U8 + 3 {
                v = self.decode_major(MAJOR_NEG_U8) as i32 + 1;
            } else {
                return Err(first);
            }
            Ok(v * -1)
        }
    }

    pub fn tag(&mut self) -> Result<u32, u8> {
        let first = self.encoded[self.index];
        if first >= MAJOR_TAG_1 && first <= MAJOR_TAG_2 {
            self.index += 1;
            Ok((first - MAJOR_TAG) as u32)
        } else if first >= MAJOR_TAG_U8 && first <= MAJOR_TAG_U8 + 3 {
            Ok(self.decode_major(MAJOR_TAG_U8) as u32)
        } else {
            Err(first)
        }
    }
    pub fn skip(&mut self) {
        self.index += 1;
    }
}
