use std::str;
const CBOR_MAX: u8 = 24;
pub(crate) const CBOR_NULL: u8 = 246;
pub(crate) const CBOR_FALSE: u8 = 244;
pub(crate) const CBOR_TRUE: u8 = 245;
const MAJOR_POS: u8 = 0;
const MAJOR_NEG: u8 = 32;
const MAJOR_O: u8 = 160;
const MAJOR_A: u8 = 128;
const MAJOR_T: u8 = 96;
const MAJOR_B: u8 = 64;
const MAJOR_TAG: u8 = 192;

pub(crate) struct Encoder {
    encoded: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Encoder {
        Encoder {
            encoded: Vec::new(),
        }
    }

    pub fn major_ai(&mut self, v: usize, major: u8) {
        if v < CBOR_MAX.into() {
            self.encoded.push(major + v as u8);
        } else {
            let add_info: Vec<u8>;
            let major_u8 = major + CBOR_MAX;
            if v <= u8::MAX.into() {
                add_info = (v as u8).to_be_bytes().to_vec();
                self.encoded.push(major_u8);
            } else if v <= u16::MAX.into() {
                self.encoded.push(major_u8 + 1);
                add_info = (v as u16).to_be_bytes().to_vec();
            } else if v <= u32::MAX.try_into().unwrap() {
                self.encoded.push(major_u8 + 2);
                add_info = (v as u32).to_be_bytes().to_vec();
            } else {
                self.encoded.push(major_u8 + 3);
                add_info = (v as u64).to_be_bytes().to_vec();
            }
            self.encoded = [&self.encoded[..], &add_info].concat();
        }
    }
    pub fn object(&mut self, len: usize) {
        self.major_ai(len, MAJOR_O);
    }
    pub fn array(&mut self, len: usize) {
        self.major_ai(len, MAJOR_A);
    }
    pub fn text(&mut self, v: &str) {
        let len = v.len();
        self.major_ai(len, MAJOR_T);
        self.encoded = [&self.encoded[..], &v.as_bytes()].concat();
    }
    pub fn bytes(&mut self, v: &[u8]) {
        let len = v.len();
        self.major_ai(len, MAJOR_B);
        self.encoded = [&self.encoded[..], v].concat();
    }
    pub fn unsigned(&mut self, v: u32) {
        self.major_ai(v as usize, MAJOR_POS);
    }
    pub fn signed(&mut self, v: i32) {
        if v >= 0 {
            self.unsigned(v as u32);
        } else {
            let val = (v + 1) * -1;
            self.major_ai(val as usize, MAJOR_NEG);
        }
    }
    pub fn tag(&mut self, v: u32) {
        self.major_ai(v as usize, MAJOR_TAG);
    }
    pub fn null(&mut self) {
        self.encoded.push(CBOR_NULL);
    }
    pub fn bool(&mut self, v: bool) {
        if v {
            self.encoded.push(CBOR_TRUE);
        } else {
            self.encoded.push(CBOR_FALSE);
        }
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
    pub fn major_ai(&mut self, major: u8) -> Result<usize, u8> {
        if self.index >= self.encoded.len() {
            return Err(255);
        }
        let first_byte = self.encoded[self.index];
        let major_u8 = major + CBOR_MAX;
        let out: usize;
        if first_byte >= major && first_byte < major_u8 {
            self.index += 1;
            out = (first_byte - major) as usize;
        } else if first_byte >= major_u8 && first_byte <= major_u8 + 3 {
            self.index += 1;
            let ai = first_byte - (major_u8);
            if ai == 0 {
                out = u8::from_be_bytes([self.encoded[self.index]]) as usize;
                self.index += 1;
            } else if ai == 1 {
                out = u16::from_be_bytes(
                    self.encoded[self.index..self.index + 2].try_into().unwrap(),
                ) as usize;
                self.index += 2;
            } else if ai == 2 {
                out = u32::from_be_bytes(
                    self.encoded[self.index..self.index + 4].try_into().unwrap(),
                ) as usize;
                self.index += 4;
            } else {
                out = u64::from_be_bytes(
                    self.encoded[self.index..self.index + 8].try_into().unwrap(),
                ) as usize;
                self.index += 8;
            }
        } else {
            return Err(first_byte);
        }
        Ok(out)
    }
    pub fn object(&mut self) -> Result<usize, u8> {
        Ok(self.major_ai(MAJOR_O)?)
    }
    pub fn array(&mut self) -> Result<usize, u8> {
        Ok(self.major_ai(MAJOR_A)?)
    }
    pub fn text(&mut self) -> Result<&str, u8> {
        let size = self.major_ai(MAJOR_T)?;
        let v = str::from_utf8(&self.encoded[self.index..(self.index + size)]).unwrap();
        self.index += size;
        Ok(v)
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>, u8> {
        let size = self.major_ai(MAJOR_B)?;
        let v = self.encoded[self.index..(self.index + size)].to_vec();
        self.index += size;
        Ok(v)
    }
    pub fn unsigned(&mut self) -> Result<u32, u8> {
        let v = self.major_ai(MAJOR_POS)? as u32;
        Ok(v)
    }

    pub fn signed(&mut self) -> Result<i32, u8> {
        let first = self.encoded[self.index];
        if first <= CBOR_MAX + 3 {
            Ok(self.unsigned().unwrap() as i32)
        } else {
            let v = (self.major_ai(MAJOR_NEG)? as i32 + 1) * -1;
            Ok(v)
        }
    }

    pub fn tag(&mut self) -> Result<u32, u8> {
        Ok(self.major_ai(MAJOR_TAG)? as u32)
    }
    pub fn bool(&mut self) -> Result<bool, u8> {
        let first = self.encoded[self.index];
        if first == CBOR_TRUE {
            self.index += 1;
            Ok(true)
        } else if first == CBOR_FALSE {
            self.index += 1;
            Ok(false)
        } else {
            Err(first)
        }
    }
    pub fn null(&mut self) -> Result<(), u8> {
        let first = self.encoded[self.index];
        if first == CBOR_NULL {
            self.index += 1;
            Ok(())
        } else {
            Err(first)
        }
    }
}
