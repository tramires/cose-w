pub(crate) mod cbor;
pub mod headers;
pub mod keys;

pub mod agent;
pub mod algs;
pub mod constants;
pub mod message;

pub(crate) mod cose_struct;

#[cfg(test)]
mod test_vecs {
    use crate::algs;
    use crate::keys;
    use crate::message::CoseMessage;
    use wasm_bindgen_test::*;
    const ELEVEN: [u8; 118] = [
        167, 1, 2, 32, 1, 2, 66, 49, 49, 33, 88, 32, 186, 197, 177, 28, 173, 143, 153, 249, 199,
        43, 5, 207, 75, 158, 38, 210, 68, 220, 24, 159, 116, 82, 40, 37, 90, 33, 154, 134, 214,
        160, 158, 255, 34, 88, 32, 32, 19, 139, 248, 45, 193, 182, 213, 98, 190, 15, 165, 74, 183,
        128, 74, 58, 100, 182, 215, 44, 207, 237, 107, 111, 182, 237, 40, 187, 252, 17, 126, 35,
        88, 32, 87, 201, 32, 119, 102, 65, 70, 232, 118, 118, 12, 149, 32, 208, 84, 170, 147, 195,
        175, 176, 78, 48, 103, 5, 219, 96, 144, 48, 133, 7, 180, 211, 4, 130, 2, 1,
    ];
    const BILBO: [u8; 249] = [
        167, 1, 2, 32, 3, 2, 88, 30, 98, 105, 108, 98, 111, 46, 98, 97, 103, 103, 105, 110, 115,
        64, 104, 111, 98, 98, 105, 116, 111, 110, 46, 101, 120, 97, 109, 112, 108, 101, 33, 88, 66,
        0, 114, 153, 44, 179, 172, 8, 236, 243, 229, 198, 61, 237, 236, 13, 81, 168, 193, 247, 158,
        242, 248, 47, 148, 243, 199, 55, 191, 93, 231, 152, 102, 113, 234, 198, 37, 254, 130, 87,
        187, 208, 57, 70, 68, 202, 170, 58, 175, 143, 39, 164, 88, 95, 187, 202, 208, 242, 69, 118,
        32, 8, 94, 92, 143, 66, 173, 34, 88, 66, 1, 220, 166, 148, 123, 206, 136, 188, 87, 144, 72,
        90, 201, 116, 39, 52, 43, 195, 95, 136, 125, 134, 214, 90, 8, 147, 119, 226, 71, 230, 11,
        170, 85, 228, 232, 80, 30, 42, 218, 87, 36, 172, 81, 214, 144, 144, 8, 3, 62, 188, 16, 172,
        153, 155, 157, 127, 92, 194, 81, 159, 63, 225, 234, 29, 148, 117, 35, 88, 66, 0, 8, 81, 56,
        221, 171, 245, 202, 151, 95, 88, 96, 249, 26, 8, 233, 29, 109, 95, 154, 118, 173, 64, 24,
        118, 106, 71, 102, 128, 181, 92, 211, 57, 232, 171, 108, 114, 181, 250, 205, 178, 162, 165,
        10, 194, 91, 208, 134, 100, 125, 211, 226, 230, 233, 158, 132, 202, 44, 54, 9, 253, 241,
        119, 254, 178, 109, 4, 130, 2, 1,
    ];
    const MERIADOC: [u8; 154] = [
        167, 1, 2, 32, 1, 2, 88, 36, 109, 101, 114, 105, 97, 100, 111, 99, 46, 98, 114, 97, 110,
        100, 121, 98, 117, 99, 107, 64, 98, 117, 99, 107, 108, 97, 110, 100, 46, 101, 120, 97, 109,
        112, 108, 101, 33, 88, 32, 101, 237, 165, 161, 37, 119, 194, 186, 232, 41, 67, 127, 227,
        56, 112, 26, 16, 170, 163, 117, 225, 187, 91, 93, 225, 8, 222, 67, 156, 8, 85, 29, 34, 88,
        32, 30, 82, 237, 117, 112, 17, 99, 247, 249, 228, 13, 223, 159, 52, 27, 61, 201, 186, 134,
        10, 247, 224, 202, 124, 167, 233, 238, 205, 0, 132, 209, 156, 35, 88, 32, 175, 249, 7, 201,
        159, 154, 211, 170, 230, 196, 205, 242, 17, 34, 188, 226, 189, 104, 181, 40, 62, 105, 7,
        21, 74, 217, 17, 132, 15, 162, 8, 207, 4, 131, 7, 1, 2,
    ];
    const PEREGRIN: [u8; 150] = [
        167, 1, 2, 32, 1, 2, 88, 33, 112, 101, 114, 101, 103, 114, 105, 110, 46, 116, 111, 111,
        107, 64, 116, 117, 99, 107, 98, 111, 114, 111, 117, 103, 104, 46, 101, 120, 97, 109, 112,
        108, 101, 33, 88, 32, 152, 245, 10, 79, 246, 192, 88, 97, 200, 134, 13, 19, 166, 56, 234,
        86, 195, 245, 173, 117, 144, 187, 251, 240, 84, 225, 199, 180, 217, 29, 98, 128, 34, 88,
        32, 240, 20, 0, 176, 137, 134, 120, 4, 184, 233, 252, 150, 195, 147, 33, 97, 241, 147, 79,
        66, 35, 6, 145, 112, 217, 36, 183, 224, 59, 248, 34, 187, 35, 88, 32, 2, 209, 247, 230,
        242, 108, 67, 212, 134, 141, 135, 206, 178, 53, 49, 97, 116, 10, 172, 241, 247, 22, 54, 71,
        152, 75, 82, 42, 132, 141, 241, 195, 4, 130, 2, 1,
    ];
    const OUR_SECRET: [u8; 55] = [
        165, 1, 4, 2, 74, 111, 117, 114, 45, 115, 101, 99, 114, 101, 116, 32, 88, 32, 132, 155, 87,
        33, 157, 174, 72, 222, 100, 109, 7, 219, 181, 51, 86, 110, 151, 102, 134, 69, 124, 20, 145,
        190, 58, 118, 220, 234, 108, 66, 113, 136, 3, 15, 4, 129, 10,
    ];
    const UID: [u8; 83] = [
        164, 1, 4, 2, 88, 36, 48, 49, 56, 99, 48, 97, 101, 53, 45, 52, 100, 57, 98, 45, 52, 55, 49,
        98, 45, 98, 102, 100, 54, 45, 101, 101, 102, 51, 49, 52, 98, 99, 55, 48, 51, 55, 32, 88,
        32, 132, 155, 87, 33, 157, 174, 72, 222, 100, 109, 7, 219, 181, 51, 86, 110, 151, 102, 134,
        69, 124, 20, 145, 190, 58, 118, 220, 234, 108, 66, 113, 136, 4, 132, 2, 9, 10, 1,
    ];

    #[wasm_bindgen_test]
    fn c11() {
        let kid = b"11".to_vec();
        let mut verify = CoseMessage::new_sign();
        verify.bytes = [
            216, 98, 132, 64, 160, 84, 84, 104, 105, 115, 32, 105, 115, 32, 116, 104, 101, 32, 99,
            111, 110, 116, 101, 110, 116, 46, 129, 131, 67, 161, 1, 38, 161, 4, 66, 49, 49, 88, 64,
            226, 174, 175, 212, 13, 105, 209, 157, 254, 110, 82, 7, 124, 93, 127, 244, 228, 8, 40,
            44, 190, 251, 93, 6, 203, 244, 20, 175, 46, 25, 217, 130, 172, 69, 172, 152, 184, 84,
            76, 144, 139, 69, 7, 222, 30, 144, 183, 23, 195, 211, 72, 22, 254, 146, 106, 43, 152,
            245, 58, 253, 47, 160, 243, 10,
        ]
        .to_vec();
        verify.init_decoder(None).unwrap();
        let v1 = verify.get_agent(kid).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = ELEVEN.to_vec();
        key.decode().unwrap();
        key.set_alg(Some(algs::ES256));
        verify.agents[v1].key(&key).unwrap();
        verify.decode(None, Some(v1)).unwrap();
    }

    #[wasm_bindgen_test]
    fn c13() {
        let kid = b"11".to_vec();
        let mut verify = CoseMessage::new_sign();
        verify.bytes = [
            216, 98, 132, 64, 161, 7, 131, 67, 161, 1, 38, 161, 4, 66, 49, 49, 88, 64, 90, 192, 94,
            40, 157, 93, 14, 27, 10, 127, 4, 138, 93, 43, 100, 56, 19, 222, 213, 11, 201, 228, 146,
            32, 244, 247, 39, 143, 133, 241, 157, 74, 119, 214, 85, 201, 211, 181, 30, 128, 90,
            116, 176, 153, 225, 224, 133, 170, 205, 151, 252, 41, 215, 47, 136, 126, 136, 2, 187,
            102, 80, 204, 235, 44, 84, 84, 104, 105, 115, 32, 105, 115, 32, 116, 104, 101, 32, 99,
            111, 110, 116, 101, 110, 116, 46, 129, 131, 67, 161, 1, 38, 161, 4, 66, 49, 49, 88, 64,
            226, 174, 175, 212, 13, 105, 209, 157, 254, 110, 82, 7, 124, 93, 127, 244, 228, 8, 40,
            44, 190, 251, 93, 6, 203, 244, 20, 175, 46, 25, 217, 130, 172, 69, 172, 152, 184, 84,
            76, 144, 139, 69, 7, 222, 30, 144, 183, 23, 195, 211, 72, 22, 254, 146, 106, 43, 152,
            245, 58, 253, 47, 160, 243, 10,
        ]
        .to_vec();

        verify.init_decoder(None).unwrap();
        let v1 = verify.get_agent(kid).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = ELEVEN.to_vec();
        key.decode().unwrap();
        key.set_alg(Some(algs::ES256));
        verify.agents[v1].key(&key).unwrap();

        verify.decode(None, Some(v1)).unwrap();

        let counter = verify.counter(b"11".to_vec(), None).unwrap()[0];
        verify.header.counters[counter].key(&key).unwrap();
        verify.counters_verify(None, counter, None).unwrap();
    }
    #[wasm_bindgen_test]
    fn c21() {
        let mut verify = CoseMessage::new_sign();
        verify.bytes = [
            210, 132, 67, 161, 1, 38, 161, 4, 66, 49, 49, 84, 84, 104, 105, 115, 32, 105, 115, 32,
            116, 104, 101, 32, 99, 111, 110, 116, 101, 110, 116, 46, 88, 64, 142, 179, 62, 76, 163,
            29, 28, 70, 90, 176, 90, 172, 52, 204, 107, 35, 213, 143, 239, 92, 8, 49, 6, 196, 210,
            90, 145, 174, 240, 176, 17, 126, 42, 249, 162, 145, 170, 50, 225, 74, 184, 52, 220, 86,
            237, 42, 34, 52, 68, 84, 126, 1, 241, 29, 59, 9, 22, 229, 164, 195, 69, 202, 203, 54,
        ]
        .to_vec();

        verify.init_decoder(None).unwrap();
        let mut key = keys::CoseKey::new();
        key.bytes = ELEVEN.to_vec();
        key.decode().unwrap();
        key.set_alg(Some(algs::ES256));
        verify.key(&key).unwrap();
        verify.decode(None, None).unwrap();
    }
    #[wasm_bindgen_test]
    fn c31() {
        let kid = b"meriadoc.brandybuck@buckland.example".to_vec();
        let msg = b"This is the content.".to_vec();
        let mut dec = CoseMessage::new_encrypt();
        dec.bytes = [
            216, 96, 132, 67, 161, 1, 1, 161, 5, 76, 201, 207, 77, 242, 254, 108, 99, 43, 247, 136,
            100, 19, 88, 36, 122, 219, 226, 112, 156, 168, 24, 251, 65, 95, 30, 93, 246, 111, 78,
            26, 81, 5, 59, 166, 214, 90, 26, 12, 82, 163, 87, 218, 122, 100, 75, 128, 112, 161, 81,
            176, 129, 131, 68, 161, 1, 56, 24, 162, 32, 164, 1, 2, 32, 1, 33, 88, 32, 152, 245, 10,
            79, 246, 192, 88, 97, 200, 134, 13, 19, 166, 56, 234, 86, 195, 245, 173, 117, 144, 187,
            251, 240, 84, 225, 199, 180, 217, 29, 98, 128, 34, 245, 4, 88, 36, 109, 101, 114, 105,
            97, 100, 111, 99, 46, 98, 114, 97, 110, 100, 121, 98, 117, 99, 107, 64, 98, 117, 99,
            107, 108, 97, 110, 100, 46, 101, 120, 97, 109, 112, 108, 101, 64,
        ]
        .to_vec();
        dec.init_decoder(None).unwrap();
        let r = dec.get_agent(kid).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = MERIADOC.to_vec();
        key.decode().unwrap();
        dec.agents[r].key(&key).unwrap();
        assert_eq!(dec.decode(None, Some(r)).unwrap(), msg);
    }
    #[wasm_bindgen_test]
    fn c34() {
        let kid = b"meriadoc.brandybuck@buckland.example".to_vec();
        let msg = b"This is the content.".to_vec();
        let aad = vec![0, 17, 187, 204, 34, 221, 68, 238, 85, 255, 102, 0, 119];
        let mut dec = CoseMessage::new_encrypt();
        dec.bytes = [
            216, 96, 132, 67, 161, 1, 1, 161, 5, 76, 2, 209, 247, 230, 242, 108, 67, 212, 134, 141,
            135, 206, 88, 36, 100, 248, 77, 145, 59, 166, 10, 118, 7, 10, 154, 72, 242, 110, 151,
            232, 99, 226, 133, 41, 216, 245, 51, 94, 95, 1, 101, 238, 233, 118, 180, 165, 246, 198,
            240, 157, 129, 131, 68, 161, 1, 56, 31, 163, 34, 88, 33, 112, 101, 114, 101, 103, 114,
            105, 110, 46, 116, 111, 111, 107, 64, 116, 117, 99, 107, 98, 111, 114, 111, 117, 103,
            104, 46, 101, 120, 97, 109, 112, 108, 101, 4, 88, 36, 109, 101, 114, 105, 97, 100, 111,
            99, 46, 98, 114, 97, 110, 100, 121, 98, 117, 99, 107, 64, 98, 117, 99, 107, 108, 97,
            110, 100, 46, 101, 120, 97, 109, 112, 108, 101, 53, 66, 1, 1, 88, 24, 65, 224, 215,
            111, 87, 157, 189, 13, 147, 106, 102, 45, 84, 216, 88, 32, 55, 222, 46, 54, 111, 222,
            28, 98,
        ]
        .to_vec();
        dec.init_decoder(None).unwrap();
        let r = dec.get_agent(kid).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = MERIADOC.to_vec();
        key.decode().unwrap();
        key.set_key_ops(vec![keys::KEY_OPS_DERIVE]);
        dec.agents[r].key(&key).unwrap();
        key = keys::CoseKey::new();
        key.bytes = PEREGRIN.to_vec();
        key.decode().unwrap();
        key.set_key_ops(vec![keys::KEY_OPS_DERIVE]);
        dec.agents[r].header.set_ecdh_key(key);
        assert_eq!(dec.decode(Some(aad), Some(r)).unwrap(), msg);
    }
    #[wasm_bindgen_test]
    fn c51() {
        let mut verify = CoseMessage::new_mac();
        verify.bytes = [
            216, 97, 133, 67, 161, 1, 15, 160, 84, 84, 104, 105, 115, 32, 105, 115, 32, 116, 104,
            101, 32, 99, 111, 110, 116, 101, 110, 116, 46, 72, 158, 18, 38, 186, 31, 129, 184, 72,
            129, 131, 64, 162, 1, 37, 4, 74, 111, 117, 114, 45, 115, 101, 99, 114, 101, 116, 64,
        ]
        .to_vec();
        verify.init_decoder(None).unwrap();
        let r = verify.get_agent(b"our-secret".to_vec()).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = OUR_SECRET.to_vec();
        key.decode().unwrap();
        key.set_alg(Some(algs::AES_MAC_256_64));
        verify.agents[r].key(&key).unwrap();
        verify.decode(None, Some(r)).unwrap();
    }
    #[wasm_bindgen_test]
    fn c52() {
        let kid = b"meriadoc.brandybuck@buckland.example".to_vec();
        let mut verify = CoseMessage::new_mac();
        verify.bytes = [
            216, 97, 133, 67, 161, 1, 5, 160, 84, 84, 104, 105, 115, 32, 105, 115, 32, 116, 104,
            101, 32, 99, 111, 110, 116, 101, 110, 116, 46, 88, 32, 129, 160, 52, 72, 172, 211, 211,
            5, 55, 110, 170, 17, 251, 63, 228, 22, 169, 85, 190, 44, 190, 126, 201, 111, 1, 44,
            153, 75, 195, 241, 106, 65, 129, 131, 68, 161, 1, 56, 26, 163, 34, 88, 33, 112, 101,
            114, 101, 103, 114, 105, 110, 46, 116, 111, 111, 107, 64, 116, 117, 99, 107, 98, 111,
            114, 111, 117, 103, 104, 46, 101, 120, 97, 109, 112, 108, 101, 4, 88, 36, 109, 101,
            114, 105, 97, 100, 111, 99, 46, 98, 114, 97, 110, 100, 121, 98, 117, 99, 107, 64, 98,
            117, 99, 107, 108, 97, 110, 100, 46, 101, 120, 97, 109, 112, 108, 101, 53, 88, 64, 77,
            133, 83, 231, 231, 79, 60, 106, 58, 157, 211, 239, 40, 106, 129, 149, 203, 248, 162,
            61, 25, 85, 140, 207, 236, 125, 52, 184, 36, 244, 45, 146, 189, 6, 189, 44, 127, 2,
            113, 240, 33, 78, 20, 31, 183, 121, 174, 40, 86, 171, 245, 133, 165, 131, 104, 176, 23,
            231, 242, 169, 229, 206, 77, 181, 64,
        ]
        .to_vec();
        verify.init_decoder(None).unwrap();
        let r = verify.get_agent(kid).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = MERIADOC.to_vec();
        key.decode().unwrap();
        verify.agents[r].key(&key).unwrap();
        key = keys::CoseKey::new();
        key.bytes = PEREGRIN.to_vec();
        key.decode().unwrap();
        verify.agents[r].header.set_ecdh_key(key);

        verify.decode(None, Some(r)).unwrap();
    }
    #[wasm_bindgen_test]
    fn c53() {
        let kid = b"018c0ae5-4d9b-471b-bfd6-eef314bc7037".to_vec();
        let mut verify = CoseMessage::new_mac();
        verify.bytes = [
            216, 97, 133, 67, 161, 1, 14, 160, 84, 84, 104, 105, 115, 32, 105, 115, 32, 116, 104,
            101, 32, 99, 111, 110, 116, 101, 110, 116, 46, 72, 54, 245, 175, 175, 11, 171, 93, 67,
            129, 131, 64, 162, 1, 36, 4, 88, 36, 48, 49, 56, 99, 48, 97, 101, 53, 45, 52, 100, 57,
            98, 45, 52, 55, 49, 98, 45, 98, 102, 100, 54, 45, 101, 101, 102, 51, 49, 52, 98, 99,
            55, 48, 51, 55, 88, 24, 113, 26, 176, 220, 47, 196, 88, 93, 206, 39, 239, 250, 103,
            129, 200, 9, 62, 186, 144, 111, 34, 123, 110, 176,
        ]
        .to_vec();
        verify.init_decoder(None).unwrap();
        let r = verify.get_agent(kid).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = UID.to_vec();
        key.decode().unwrap();
        key.set_alg(Some(algs::AES_MAC_128_64));
        verify.agents[r].key(&key).unwrap();

        verify.decode(None, Some(r)).unwrap();
    }
    #[wasm_bindgen_test]
    fn c61() {
        let mut verify = CoseMessage::new_mac();
        verify.bytes = [
            209, 132, 67, 161, 1, 15, 160, 84, 84, 104, 105, 115, 32, 105, 115, 32, 116, 104, 101,
            32, 99, 111, 110, 116, 101, 110, 116, 46, 72, 114, 96, 67, 116, 80, 39, 33, 79,
        ]
        .to_vec();
        verify.init_decoder(None).unwrap();
        let mut key = keys::CoseKey::new();
        key.bytes = OUR_SECRET.to_vec();
        key.decode().unwrap();
        key.set_alg(Some(algs::AES_MAC_256_64));
        verify.key(&key).unwrap();
        verify.decode(None, None).unwrap();
    }
    #[wasm_bindgen_test]
    fn rsa() {
        let kid = b"meriadoc.brandybuck@rsa.example".to_vec();
        let mut verify = CoseMessage::new_sign();
        verify.bytes = vec![
            216, 98, 132, 67, 161, 3, 0, 160, 84, 84, 104, 105, 115, 32, 105, 115, 32, 116, 104,
            101, 32, 99, 111, 110, 116, 101, 110, 116, 46, 129, 131, 68, 161, 1, 56, 36, 161, 4,
            88, 31, 109, 101, 114, 105, 97, 100, 111, 99, 46, 98, 114, 97, 110, 100, 121, 98, 117,
            99, 107, 64, 114, 115, 97, 46, 101, 120, 97, 109, 112, 108, 101, 89, 1, 0, 58, 212, 2,
            112, 116, 152, 153, 149, 242, 94, 22, 127, 153, 201, 180, 9, 111, 220, 92, 36, 45, 67,
            141, 48, 56, 42, 231, 179, 15, 131, 200, 141, 91, 94, 190, 203, 100, 210, 37, 109, 88,
            211, 204, 229, 196, 125, 52, 59, 250, 83, 43, 17, 124, 45, 4, 223, 63, 178, 6, 121,
            169, 156, 243, 85, 90, 125, 174, 96, 152, 189, 18, 59, 15, 52, 65, 161, 229, 14, 137,
            124, 186, 161, 177, 124, 225, 113, 235, 171, 32, 174, 46, 16, 241, 109, 110, 233, 24,
            211, 122, 241, 2, 23, 89, 121, 190, 101, 235, 206, 222, 180, 117, 25, 52, 110, 163,
            237, 109, 19, 181, 116, 27, 198, 55, 66, 174, 49, 52, 43, 16, 180, 111, 233, 63, 57,
            181, 95, 221, 110, 50, 18, 143, 216, 180, 118, 254, 216, 143, 103, 31, 48, 77, 9, 67,
            210, 199, 163, 59, 206, 72, 223, 8, 225, 248, 144, 207, 90, 205, 163, 239, 70, 218, 33,
            152, 28, 58, 104, 124, 255, 248, 94, 235, 39, 106, 152, 97, 47, 56, 214, 238, 99, 100,
            72, 89, 214, 106, 154, 212, 153, 57, 234, 41, 15, 122, 159, 223, 237, 154, 241, 36,
            105, 48, 245, 34, 203, 140, 105, 9, 86, 125, 203, 226, 114, 151, 22, 203, 24, 163, 30,
            111, 35, 29, 179, 214, 154, 122, 67, 42, 163, 214, 250, 29, 239, 156, 150, 89, 97, 107,
            235, 98, 111, 21, 131, 120, 224, 251, 221,
        ];

        verify.init_decoder(None).unwrap();
        let v1 = verify.get_agent(kid).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.set_alg(Some(algs::PS256));
        key.set_kty(Some(keys::RSA));
        key.set_n(Some(vec![
            188, 126, 41, 208, 223, 126, 32, 204, 157, 200, 213, 9, 224, 246, 136, 149, 146, 42,
            240, 239, 69, 33, 144, 212, 2, 198, 27, 85, 67, 52, 167, 191, 145, 201, 165, 112, 36,
            15, 153, 79, 174, 27, 105, 3, 91, 207, 173, 79, 126, 36, 158, 178, 96, 135, 194, 102,
            94, 124, 149, 140, 150, 123, 21, 23, 65, 61, 195, 249, 122, 67, 22, 145, 165, 153, 155,
            37, 124, 198, 205, 53, 107, 173, 22, 141, 146, 155, 139, 174, 144, 32, 117, 14, 116,
            207, 96, 246, 253, 53, 214, 187, 63, 201, 63, 194, 137, 0, 71, 134, 148, 245, 8, 179,
            62, 124, 0, 226, 79, 144, 237, 243, 116, 87, 252, 62, 142, 252, 253, 47, 66, 48, 99, 1,
            168, 32, 90, 183, 64, 81, 83, 49, 213, 193, 143, 12, 100, 212, 164, 59, 229, 47, 196,
            64, 64, 15, 107, 252, 85, 138, 110, 50, 136, 76, 42, 245, 111, 41, 229, 197, 39, 128,
            206, 167, 40, 95, 92, 5, 127, 192, 223, 218, 35, 45, 10, 218, 104, 27, 1, 73, 93, 157,
            14, 50, 25, 102, 51, 88, 142, 40, 158, 89, 3, 95, 246, 100, 240, 86, 24, 159, 47, 16,
            254, 5, 130, 123, 121, 108, 50, 110, 62, 116, 143, 250, 124, 88, 158, 210, 115, 201,
            196, 52, 54, 205, 219, 74, 106, 34, 82, 62, 248, 188, 178, 34, 22, 21, 183, 153, 150,
            111, 26, 186, 91, 200, 75, 122, 39, 207,
        ]));
        key.set_e(Some(vec![1, 0, 1]));
        key.set_key_ops(vec![keys::KEY_OPS_VERIFY]);
        verify.agents[v1].key(&key).unwrap();

        verify.decode(None, Some(v1)).unwrap();
    }
}
