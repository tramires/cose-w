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
    use crate::agent;
    use crate::algs;
    use crate::headers;
    use crate::keys;
    use crate::message::CoseMessage;
    use wasm_bindgen_test::*;

    fn remove_probabilistic(output: &mut Vec<u8>, expected: &mut Vec<u8>, rem: Vec<u8>) {
        let i = expected.windows(rem.len()).position(|w| w == rem).unwrap();
        expected.drain(i..i + rem.len());
        output.drain(i..i + rem.len());
    }

    fn get_test_vec(id: &str) -> Vec<u8> {
        let test_vecs = include_str!("../test_params/test_vecs.csv");
        let mut msg = vec![];
        for line in test_vecs.lines().skip(1) {
            let kp: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
            if kp[0] == id {
                msg = hex::decode(kp[1]).unwrap();
            }
        }
        msg
    }

    fn get_key(kid: Vec<u8>, public: bool) -> keys::CoseKey {
        let key_set;
        if public {
            key_set = include_str!("../test_params/pub_key_set");
        } else {
            key_set = include_str!("../test_params/priv_key_set");
        }
        let mut cose_ks = keys::CoseKeySet::new();
        cose_ks.set_bytes(hex::decode(key_set.trim()).unwrap());
        cose_ks.decode().unwrap();
        cose_ks.get_key(kid).unwrap()
    }

    #[wasm_bindgen_test]
    fn c11() {
        let kid = b"11".to_vec();
        let mut verify = CoseMessage::new_sign();
        verify.set_bytes(get_test_vec("C11"));
        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(kid.clone()).unwrap()[0];
        let key = get_key(kid, true);
        verify.set_agent_key(i, &key).unwrap();
        verify.decode(None, Some(i)).unwrap();

        verify.payload = b"This is not the content.".to_vec();
        assert!(verify.decode(None, Some(i)).is_err());
    }

    #[wasm_bindgen_test]
    fn prod_c11() {
        let kid = b"11".to_vec();
        let payload = b"This is the content.".to_vec();
        let mut sign = CoseMessage::new_sign();
        sign.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_kid(kid.clone(), false, false);
        header.set_alg(algs::ES256, true, false);

        let mut key = get_key(kid.clone(), false);

        let mut agent = agent::CoseAgent::new();
        agent.set_header(header);
        agent.key(&key).unwrap();

        sign.add_agent(&mut agent).unwrap();
        sign.secure_content(None).unwrap();

        let mut output = sign.encode(true).unwrap();
        let mut expected = get_test_vec("C11");

        // Remove probabilistic
        remove_probabilistic(&mut output, &mut expected, hex::decode("e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a").unwrap());
        assert_eq!(output, expected);

        // Verify
        let mut verify = CoseMessage::new_sign();
        verify.set_bytes(sign.bytes);
        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(kid.clone()).unwrap()[0];
        key = get_key(kid, true);
        verify.set_agent_key(i, &key).unwrap();
        verify.decode(None, Some(i)).unwrap();
    }

    #[wasm_bindgen_test]
    fn c12() {
        let kid = b"11".to_vec();
        let kid2 = b"bilbo.baggins@hobbiton.example".to_vec();

        let mut verify = CoseMessage::new_sign();
        verify.set_bytes(get_test_vec("C12"));
        verify.init_decoder(None).unwrap();

        let i = verify.get_agent(kid.clone()).unwrap()[0];
        let key = get_key(kid, true);
        verify.set_agent_key(i, &key).unwrap();
        verify.decode(None, Some(i)).unwrap();

        let i2 = verify.get_agent(kid2.clone()).unwrap()[0];
        let key2 = get_key(kid2, true);
        verify.set_agent_key(i2, &key2).unwrap();
        verify.decode(None, Some(i2)).unwrap();

        verify.payload = b"This is not the content.".to_vec();
        assert!(verify.decode(None, Some(i)).is_err());
    }

    #[wasm_bindgen_test]
    fn prod_c12() {
        let kid = b"11".to_vec();
        let kid2 = b"bilbo.baggins@hobbiton.example".to_vec();
        let payload = b"This is the content.".to_vec();

        let mut sign = CoseMessage::new_sign();
        sign.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_kid(kid.clone(), false, false);
        header.set_alg(algs::ES256, true, false);

        let mut key = get_key(kid.clone(), false);

        let mut agent = agent::CoseAgent::new();
        agent.set_header(header);
        agent.key(&key).unwrap();
        sign.add_agent(&mut agent).unwrap();

        let mut header = headers::CoseHeader::new();
        header.set_kid(kid2.clone(), false, false);
        header.set_alg(algs::ES512, true, false);

        let mut key2 = get_key(kid2.clone(), false);

        agent = agent::CoseAgent::new();
        agent.set_header(header);
        agent.key(&key2).unwrap();

        sign.add_agent(&mut agent).unwrap();
        sign.secure_content(None).unwrap();

        let mut output = sign.encode(true).unwrap();
        let mut expected = get_test_vec("C12");

        // Remove probabilistic
        remove_probabilistic(&mut output, &mut expected, hex::decode("e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a").unwrap());
        remove_probabilistic(&mut output, &mut expected, hex::decode("00a2d28a7c2bdb1587877420f65adf7d0b9a06635dd1de64bb62974c863f0b160dd2163734034e6ac003b01e8705524c5c4ca479a952f0247ee8cb0b4fb7397ba08d009e0c8bf482270cc5771aa143966e5a469a09f613488030c5b07ec6d722e3835adb5b2d8c44e95ffb13877dd2582866883535de3bb03d01753f83ab87bb4f7a0297").unwrap());

        assert_eq!(output, expected);

        // Verify
        let mut verify = CoseMessage::new_sign();
        verify.set_bytes(sign.bytes);
        verify.init_decoder(None).unwrap();

        let i = verify.get_agent(kid.clone()).unwrap()[0];
        key = get_key(kid, true);
        verify.set_agent_key(i, &key).unwrap();
        verify.decode(None, Some(i)).unwrap();

        let i2 = verify.get_agent(kid2.clone()).unwrap()[0];
        key2 = get_key(kid2, true);
        verify.set_agent_key(i2, &key2).unwrap();
        verify.decode(None, Some(i2)).unwrap();
    }

    #[wasm_bindgen_test]
    fn c13() {
        let kid = b"11".to_vec();
        let mut verify = CoseMessage::new_sign();
        verify.set_bytes(get_test_vec("C13"));

        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(kid.clone()).unwrap()[0];
        let key = get_key(kid, true);
        verify.set_agent_key(i, &key).unwrap();

        verify.decode(None, Some(i)).unwrap();

        let counter = verify.counter(b"11".to_vec(), None).unwrap()[0];
        verify.set_counter_key(counter, None, &key).unwrap();
        verify.counters_verify(None, counter, None).unwrap();

        verify.payload = b"This is not the content.".to_vec();
        assert!(verify.decode(None, Some(i)).is_err());

        verify.set_counter_key(counter, None, &key).unwrap();
        assert!(verify.counters_verify(None, counter, None).is_err());
    }

    #[wasm_bindgen_test]
    fn prod_c13() {
        let kid = b"11".to_vec();
        let payload = b"This is the content.".to_vec();
        let mut sign = CoseMessage::new_sign();
        sign.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_kid(kid.clone(), false, false);
        header.set_alg(algs::ES256, true, false);

        let mut key = get_key(kid.clone(), false);

        let mut agent = agent::CoseAgent::new();
        agent.set_header(header);
        agent.key(&key).unwrap();

        sign.add_agent(&mut agent).unwrap();
        sign.secure_content(None).unwrap();

        let mut counter = agent::CoseAgent::new_counter_sig();

        let mut header = headers::CoseHeader::new();
        header.set_kid(kid.clone(), false, false);
        header.set_alg(algs::ES256, true, false);

        counter.set_header(header);
        counter.key(&key).unwrap();

        sign.counter_sig(None, &mut counter, None).unwrap();
        sign.add_counter_sig(counter, None).unwrap();

        let mut output = sign.encode(true).unwrap();
        let mut expected = get_test_vec("C13");

        // Remove probabilistic
        remove_probabilistic(&mut output, &mut expected, hex::decode("5ac05e289d5d0e1b0a7f048a5d2b643813ded50bc9e49220f4f7278f85f19d4a77d655c9d3b51e805a74b099e1e085aacd97fc29d72f887e8802bb6650cceb2c").unwrap());
        remove_probabilistic(&mut output, &mut expected, hex::decode("e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a").unwrap());

        assert_eq!(output, expected);

        // Verify
        let mut verify = CoseMessage::new_sign();
        verify.set_bytes(sign.bytes);

        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(kid.clone()).unwrap()[0];
        key = get_key(kid, true);
        verify.set_agent_key(i, &key).unwrap();

        verify.decode(None, Some(i)).unwrap();

        let counter = verify.counter(b"11".to_vec(), None).unwrap()[0];
        verify.set_counter_key(counter, None, &key).unwrap();
        verify.counters_verify(None, counter, None).unwrap();
    }

    #[wasm_bindgen_test]
    fn c21() {
        let mut verify = CoseMessage::new_sign();
        verify.set_bytes(get_test_vec("C21"));
        verify.init_decoder(None).unwrap();

        let key = get_key(verify.header.kid.clone().unwrap(), true);

        verify.key(&key).unwrap();
        verify.decode(None, None).unwrap();

        verify.payload = b"This is not the content.".to_vec();
        assert!(verify.decode(None, None).is_err());
    }

    #[wasm_bindgen_test]
    fn prod_c21() {
        let kid = b"11".to_vec();
        let payload = b"This is the content.".to_vec();
        let mut sign = CoseMessage::new_sign();
        sign.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_kid(kid.clone(), false, false);
        header.set_alg(algs::ES256, true, false);
        sign.set_header(header);

        let mut key = get_key(kid, false);

        sign.key(&key).unwrap();

        sign.secure_content(None).unwrap();

        let mut output = sign.encode(true).unwrap();
        let mut expected = get_test_vec("C21");

        // Remove probabilistic for comparison
        remove_probabilistic(&mut output, &mut expected, hex::decode("8EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF0B0117E2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36").unwrap());

        assert_eq!(output, expected);

        // Verify
        let mut verify = CoseMessage::new_sign();
        verify.set_bytes(sign.bytes);
        verify.init_decoder(None).unwrap();

        key = get_key(verify.header.kid.clone().unwrap(), true);

        verify.key(&key).unwrap();
        verify.decode(None, None).unwrap();
    }

    #[wasm_bindgen_test]
    fn c31() {
        let kid = b"meriadoc.brandybuck@buckland.example".to_vec();
        let msg = b"This is the content.".to_vec();
        let mut dec = CoseMessage::new_encrypt();
        dec.set_bytes(get_test_vec("C31"));
        dec.init_decoder(None).unwrap();
        let i = dec.get_agent(kid.clone()).unwrap()[0];
        let key = get_key(kid, false);

        dec.set_agent_key(i, &key).unwrap();
        assert_eq!(dec.decode(None, Some(i)).unwrap(), msg);
    }

    #[wasm_bindgen_test]
    fn prod_c31() {
        let kid = b"meriadoc.brandybuck@buckland.example".to_vec();
        let payload = b"This is the content.".to_vec();
        let mut enc = CoseMessage::new_encrypt();
        enc.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::A128GCM, true, false);
        header.set_iv(
            vec![201, 207, 77, 242, 254, 108, 99, 43, 247, 136, 100, 19],
            false,
            false,
        );
        enc.set_header(header);

        let mut key = get_key(kid.clone(), true);

        let mut agent = agent::CoseAgent::new();
        header = headers::CoseHeader::new();
        header.set_alg(algs::ECDH_ES_HKDF_256, true, false);

        agent.set_header(header);
        agent.key(&key).unwrap();

        let mut key1 = get_key(b"peregrin.took@tuckborough.example".to_vec(), false);
        key1.set_y_parity(Some(true));

        agent.ephemeral_key(&key1, false, false);
        agent.header.set_kid(kid.clone(), false, false);

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(None).unwrap();

        let bytes = enc.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C31"));

        // Decrypt
        let msg = b"This is the content.".to_vec();
        let mut dec = CoseMessage::new_encrypt();
        dec.set_bytes(enc.bytes);
        dec.init_decoder(None).unwrap();
        let i = dec.get_agent(kid.clone()).unwrap()[0];
        key = get_key(kid, false);

        dec.set_agent_key(i, &key).unwrap();
        assert_eq!(dec.decode(None, Some(i)).unwrap(), msg);
    }

    #[wasm_bindgen_test]
    fn c32() {
        let kid = b"our-secret".to_vec();
        let msg = b"This is the content.".to_vec();
        let mut dec = CoseMessage::new_encrypt();
        dec.set_bytes(get_test_vec("C32"));
        dec.init_decoder(None).unwrap();
        let i = dec.get_agent(kid.clone()).unwrap()[0];

        let key = get_key(kid, false);

        dec.set_party_identity(i, b"lighting-client".to_vec(), true);
        dec.set_party_identity(i, b"lighting-server".to_vec(), false);
        dec.set_pub_other(i, b"Encryption Example 02".to_vec());
        dec.set_agent_key(i, &key).unwrap();
        assert_eq!(dec.decode(None, Some(i)).unwrap(), msg);
    }

    #[wasm_bindgen_test]
    fn prod_c32() {
        let kid = b"our-secret".to_vec();
        let salt = b"aabbccddeeffgghh".to_vec();
        let payload = b"This is the content.".to_vec();
        let mut enc = CoseMessage::new_encrypt();
        enc.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::AES_CCM_16_64_128, true, false);
        header.set_iv(
            vec![137, 245, 47, 101, 161, 197, 128, 147, 59, 82, 97, 167, 108],
            false,
            false,
        );
        enc.set_header(header);

        let mut key = get_key(kid.clone(), false);

        let mut agent = agent::CoseAgent::new();
        header = headers::CoseHeader::new();
        header.set_alg(algs::DIRECT_HKDF_SHA_256, true, false);
        header.set_salt(salt, false, false);
        header.set_kid(kid.clone(), false, false);
        header.set_party_identity(b"lighting-client".to_vec(), false, false, true, false);
        header.set_party_identity(b"lighting-server".to_vec(), false, false, false, false);
        header.set_pub_other(Some(b"Encryption Example 02".to_vec()));

        agent.set_header(header);
        agent.key(&key).unwrap();

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(None).unwrap();

        let bytes = enc.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C32"));

        // Decrypt
        let msg = b"This is the content.".to_vec();
        let mut dec = CoseMessage::new_encrypt();
        dec.set_bytes(enc.bytes);
        dec.init_decoder(None).unwrap();
        let i = dec.get_agent(kid.clone()).unwrap()[0];

        key = get_key(kid, false);

        dec.set_party_identity(i, b"lighting-client".to_vec(), true);
        dec.set_party_identity(i, b"lighting-server".to_vec(), false);
        dec.set_pub_other(i, b"Encryption Example 02".to_vec());
        dec.set_agent_key(i, &key).unwrap();
        assert_eq!(dec.decode(None, Some(i)).unwrap(), msg);
    }

    #[wasm_bindgen_test]
    fn c33() {
        let mut dec = CoseMessage::new_encrypt();
        let msg = b"This is the content.".to_vec();
        dec.set_bytes(get_test_vec("C33"));
        dec.init_decoder(None).unwrap();

        let key = get_key(dec.agents[0].header.kid.clone().unwrap(), false);

        dec.set_agent_key(0, &key).unwrap();
        let decoded = dec.decode(None, Some(0)).unwrap();
        assert_eq!(decoded, msg);

        let kid2 = b"bilbo.baggins@hobbiton.example".to_vec();
        let counter = dec.counter(kid2.clone(), None).unwrap()[0];
        let key2 = get_key(kid2, true);

        dec.set_counter_key(counter, None, &key2).unwrap();
        dec.counters_verify(None, counter, None).unwrap();
    }

    #[wasm_bindgen_test]
    fn prod_c33() {
        let kid = b"meriadoc.brandybuck@buckland.example".to_vec();
        let eph_kid = b"peregrin.took@tuckborough.example".to_vec();
        let counter_kid = b"bilbo.baggins@hobbiton.example".to_vec();
        let payload = b"This is the content.".to_vec();

        let mut enc = CoseMessage::new_encrypt();
        enc.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::A128GCM, true, false);
        header.set_iv(
            hex::decode("c9cf4df2fe6c632bf7886413").unwrap().to_vec(),
            false,
            false,
        );
        enc.set_header(header);

        let mut key = get_key(kid.clone(), true);

        let mut agent = agent::CoseAgent::new();
        header = headers::CoseHeader::new();
        header.set_alg(algs::ECDH_ES_HKDF_256, true, false);

        agent.set_header(header);
        agent.key(&key).unwrap();

        let mut eph_key = get_key(eph_kid, false);

        eph_key.set_y_parity(Some(true));
        agent.ephemeral_key(&eph_key, false, false);
        agent.header.set_kid(kid.clone(), false, false);

        enc.add_agent(&mut agent).unwrap();
        enc.secure_content(None).unwrap();

        let mut counter = agent::CoseAgent::new_counter_sig();

        let mut header = headers::CoseHeader::new();
        header.set_kid(counter_kid.clone(), false, false);
        header.set_alg(algs::ES512, true, false);

        counter.set_header(header);

        let mut counter_key = get_key(counter_kid.clone(), false);

        counter.key(&counter_key).unwrap();
        enc.counter_sig(None, &mut counter, None).unwrap();
        enc.add_counter_sig(counter, None).unwrap();

        let mut output = enc.encode(true).unwrap();
        let mut expected = get_test_vec("C33");

        // Remove probabilistic for comparison
        remove_probabilistic(&mut output, &mut expected, hex::decode("00929663c8789bb28177ae28467e66377da12302d7f9594d2999afa5dfa531294f8896f2b6cdf1740014f4c7f1a358e3a6cf57f4ed6fb02fcf8f7aa989f5dfd07f0700a3a7d8f3c604ba70fa9411bd10c2591b483e1d2c31de003183e434d8fba18f17a4c7e3dfa003ac1cf3d30d44d2533c4989d3ac38c38b71481cc3430c9d65e7ddff").unwrap());

        assert_eq!(output, expected);

        // Decrypt

        let msg = b"This is the content.".to_vec();
        let mut dec = CoseMessage::new_encrypt();
        dec.set_bytes(enc.bytes);
        dec.init_decoder(None).unwrap();

        key = get_key(dec.agents[0].header.kid.clone().unwrap(), false);

        dec.set_agent_key(0, &key).unwrap();
        let decoded = dec.decode(None, Some(0)).unwrap();
        assert_eq!(decoded, msg);

        let counter_i = dec.counter(counter_kid.clone(), None).unwrap()[0];
        counter_key = get_key(counter_kid, false);

        dec.set_counter_key(counter_i, None, &counter_key).unwrap();
        dec.counters_verify(None, counter_i, None).unwrap();
    }

    #[wasm_bindgen_test]
    fn c34() {
        let kid = b"meriadoc.brandybuck@buckland.example".to_vec();
        let msg = b"This is the content.".to_vec();
        let aad = vec![0, 17, 187, 204, 34, 221, 68, 238, 85, 255, 102, 0, 119];
        let mut dec = CoseMessage::new_encrypt();
        dec.set_bytes(get_test_vec("C34"));
        dec.init_decoder(None).unwrap();
        let i = dec.get_agent(kid.clone()).unwrap()[0];
        let mut key = get_key(kid, false);

        key.set_key_ops(vec![keys::KEY_OPS_DERIVE]);
        dec.set_agent_key(i, &key).unwrap();
        key = get_key(b"peregrin.took@tuckborough.example".to_vec(), false);
        key.set_key_ops(vec![keys::KEY_OPS_DERIVE]);
        dec.set_ecdh_key(i, key);
        assert_eq!(dec.decode(Some(aad), Some(i)).unwrap(), msg);
    }
    #[wasm_bindgen_test]
    fn prod_c34() {
        let kid = b"meriadoc.brandybuck@buckland.example".to_vec();
        let aad = vec![0, 17, 187, 204, 34, 221, 68, 238, 85, 255, 102, 0, 119];
        let payload = b"This is the content.".to_vec();
        let mut enc = CoseMessage::new_encrypt();
        enc.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::A128GCM, true, false);
        header.set_iv(
            vec![2, 209, 247, 230, 242, 108, 67, 212, 134, 141, 135, 206],
            false,
            false,
        );
        enc.set_header(header);

        let mut key = get_key(kid.clone(), true);

        let mut agent = agent::CoseAgent::new();
        header = headers::CoseHeader::new();
        header.set_alg(algs::ECDH_SS_A128KW, true, false);

        agent.set_header(header);
        agent.key(&key).unwrap();

        let key1 = get_key(b"peregrin.took@tuckborough.example".to_vec(), false);

        agent.header.set_static_kid(
            b"peregrin.took@tuckborough.example".to_vec(),
            &key1,
            false,
            false,
        );
        agent.header.set_kid(kid.clone(), false, false);
        agent.header.set_party_nonce(vec![1, 1], false, false, true);

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(Some(aad.clone())).unwrap();

        let mut output = enc.encode(true).unwrap();
        let mut expected = get_test_vec("C34");

        // Remove ciphertext and cek (probabilistic) for comparison
        remove_probabilistic(
            &mut output,
            &mut expected,
            hex::decode("64f84d913ba60a76070a9a48f26e97e863e28529d8f5335e5f0165eee976b4a5f6c6f09d")
                .unwrap(),
        );
        remove_probabilistic(
            &mut output,
            &mut expected,
            hex::decode("41e0d76f579dbd0d936a662d54d8582037de2e366fde1c62").unwrap(),
        );

        assert_eq!(output, expected);

        // Decrypt
        let msg = b"This is the content.".to_vec();

        let mut dec = CoseMessage::new_encrypt();
        dec.set_bytes(enc.bytes);
        dec.init_decoder(None).unwrap();
        let i = dec.get_agent(kid.clone()).unwrap()[0];
        key = get_key(kid, false);
        key.set_key_ops(vec![keys::KEY_OPS_DERIVE]);

        dec.set_agent_key(i, &key).unwrap();
        key = get_key(b"peregrin.took@tuckborough.example".to_vec(), false);
        key.set_key_ops(vec![keys::KEY_OPS_DERIVE]);
        dec.set_ecdh_key(i, key);
        assert_eq!(dec.decode(Some(aad), Some(i)).unwrap(), msg);
    }

    #[wasm_bindgen_test]
    fn c41() {
        let msg = b"This is the content.".to_vec();
        let mut dec = CoseMessage::new_encrypt();
        dec.set_bytes(get_test_vec("C41"));
        dec.init_decoder(None).unwrap();
        let key = get_key(b"our-secret2".to_vec(), false);
        dec.key(&key).unwrap();
        assert_eq!(dec.decode(None, None).unwrap(), msg);
    }

    #[wasm_bindgen_test]
    fn prod_c41() {
        let payload = b"This is the content.".to_vec();
        let mut enc = CoseMessage::new_encrypt();
        enc.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::AES_CCM_16_64_128, true, false);
        header.set_iv(
            vec![137, 245, 47, 101, 161, 197, 128, 147, 59, 82, 97, 167, 140],
            false,
            false,
        );
        enc.set_header(header);

        let mut key = get_key(b"our-secret2".to_vec(), false);

        enc.key(&key).unwrap();
        enc.secure_content(None).unwrap();

        let bytes = enc.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C41"));

        // Decrypt

        let msg = b"This is the content.".to_vec();
        let mut dec = CoseMessage::new_encrypt();
        dec.set_bytes(get_test_vec("C41"));
        dec.init_decoder(None).unwrap();
        key = get_key(b"our-secret2".to_vec(), false);
        dec.key(&key).unwrap();
        assert_eq!(dec.decode(None, None).unwrap(), msg);
    }

    #[wasm_bindgen_test]
    fn c42() {
        let msg = b"This is the content.".to_vec();
        let mut dec = CoseMessage::new_encrypt();
        dec.set_bytes(get_test_vec("C42"));
        dec.init_decoder(None).unwrap();
        let mut key = get_key(b"our-secret2".to_vec(), false);
        key.set_base_iv(Some(vec![137, 245, 47, 101, 161, 197, 128, 147]));
        dec.key(&key).unwrap();
        assert_eq!(dec.decode(None, None).unwrap(), msg);
    }

    #[wasm_bindgen_test]
    fn prod_c42() {
        let payload = b"This is the content.".to_vec();
        let mut enc = CoseMessage::new_encrypt();
        enc.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::AES_CCM_16_64_128, true, false);
        header.set_partial_iv(vec![97, 167], false, false);
        enc.set_header(header);

        let mut key = get_key(b"our-secret2".to_vec(), false);
        key.set_base_iv(Some(vec![137, 245, 47, 101, 161, 197, 128, 147]));

        enc.key(&key).unwrap();
        enc.secure_content(None).unwrap();

        let bytes = enc.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C42"));

        // Decrypt
        let msg = b"This is the content.".to_vec();
        let mut dec = CoseMessage::new_encrypt();
        dec.set_bytes(enc.bytes);
        dec.init_decoder(None).unwrap();
        key = get_key(b"our-secret2".to_vec(), false);
        key.set_base_iv(Some(vec![137, 245, 47, 101, 161, 197, 128, 147]));
        dec.key(&key).unwrap();
        assert_eq!(dec.decode(None, None).unwrap(), msg);
    }

    #[wasm_bindgen_test]
    fn c51() {
        let mut verify = CoseMessage::new_mac();
        verify.set_bytes(get_test_vec("C51"));
        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(b"our-secret".to_vec()).unwrap()[0];
        let key = get_key(b"our-secret".to_vec(), false);
        verify.set_agent_key(i, &key).unwrap();
        verify.decode(None, Some(i)).unwrap();

        verify.payload = b"This is not the content.".to_vec();
        assert!(verify.decode(None, Some(i)).is_err());
    }

    #[wasm_bindgen_test]
    fn prod_c51() {
        let kid = b"our-secret".to_vec();
        let payload = b"This is the content.".to_vec();
        let mut mac = CoseMessage::new_mac();
        mac.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::AES_MAC_256_64, true, false);
        mac.set_header(header);

        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::DIRECT, false, false);
        header.set_kid(kid, false, false);

        let mut key = get_key(b"our-secret".to_vec(), false);

        let mut agent = agent::CoseAgent::new();
        agent.set_header(header);
        agent.key(&key).unwrap();

        mac.add_agent(&mut agent).unwrap();
        mac.secure_content(None).unwrap();

        let bytes = mac.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C51"));

        // Verify MAC
        let mut verify = CoseMessage::new_mac();
        verify.set_bytes(mac.bytes);
        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(b"our-secret".to_vec()).unwrap()[0];
        key = get_key(b"our-secret".to_vec(), false);
        verify.set_agent_key(i, &key).unwrap();
        verify.decode(None, Some(i)).unwrap();
    }

    #[wasm_bindgen_test]
    fn c52() {
        let kid = b"meriadoc.brandybuck@buckland.example".to_vec();
        let mut verify = CoseMessage::new_mac();
        verify.set_bytes(get_test_vec("C52"));
        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(kid.clone()).unwrap()[0];
        let mut key = get_key(kid, false);
        verify.set_agent_key(i, &key).unwrap();
        key = get_key(b"peregrin.took@tuckborough.example".to_vec(), true);
        verify.set_ecdh_key(i, key);

        verify.decode(None, Some(i)).unwrap();

        verify.payload = b"This is not the content.".to_vec();
        assert!(verify.decode(None, Some(i)).is_err());
    }

    #[wasm_bindgen_test]
    fn prod_c52() {
        let kid = b"meriadoc.brandybuck@buckland.example".to_vec();
        let payload = b"This is the content.".to_vec();
        let mut mac = CoseMessage::new_mac();
        mac.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::HMAC_256_256, true, false);
        mac.set_header(header);

        let mut key = get_key(kid.clone(), true);

        let mut agent = agent::CoseAgent::new();
        header = headers::CoseHeader::new();
        header.set_alg(algs::ECDH_SS_HKDF_256, true, false);

        let key1 = get_key(b"peregrin.took@tuckborough.example".to_vec(), false);

        header.set_static_kid(
            b"peregrin.took@tuckborough.example".to_vec(),
            &key1,
            false,
            false,
        );
        header.set_kid(kid.clone(), false, false);
        header.set_party_nonce(
            vec![
                77, 133, 83, 231, 231, 79, 60, 106, 58, 157, 211, 239, 40, 106, 129, 149, 203, 248,
                162, 61, 25, 85, 140, 207, 236, 125, 52, 184, 36, 244, 45, 146, 189, 6, 189, 44,
                127, 2, 113, 240, 33, 78, 20, 31, 183, 121, 174, 40, 86, 171, 245, 133, 165, 131,
                104, 176, 23, 231, 242, 169, 229, 206, 77, 181,
            ],
            false,
            false,
            true,
        );

        agent.set_header(header);
        agent.key(&key).unwrap();

        mac.add_agent(&mut agent).unwrap();

        mac.secure_content(None).unwrap();

        let bytes = mac.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C52"));

        // Verify MAC
        let mut verify = CoseMessage::new_mac();
        verify.set_bytes(mac.bytes);
        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(kid.clone()).unwrap()[0];
        key = get_key(kid, false);
        verify.set_agent_key(i, &key).unwrap();
        key = get_key(b"peregrin.took@tuckborough.example".to_vec(), true);
        verify.set_ecdh_key(i, key);

        verify.decode(None, Some(i)).unwrap();
    }

    #[wasm_bindgen_test]
    fn c53() {
        let kid = b"018c0ae5-4d9b-471b-bfd6-eef314bc7037".to_vec();
        let mut verify = CoseMessage::new_mac();
        verify.set_bytes(get_test_vec("C53"));
        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(kid.clone()).unwrap()[0];
        let key = get_key(kid, false);
        verify.set_agent_key(i, &key).unwrap();

        verify.decode(None, Some(i)).unwrap();

        verify.payload = b"This is not the content.".to_vec();
        assert!(verify.decode(None, Some(i)).is_err());
    }
    #[wasm_bindgen_test]
    fn prod_c53() {
        let kid = b"018c0ae5-4d9b-471b-bfd6-eef314bc7037".to_vec();
        let payload = b"This is the content.".to_vec();
        let mut mac = CoseMessage::new_mac();
        mac.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::AES_MAC_128_64, true, false);
        mac.set_header(header);

        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::A256KW, false, false);
        header.set_kid(kid.clone(), false, false);

        let mut key = get_key(kid.clone(), false);

        let mut agent = agent::CoseAgent::new();
        agent.set_header(header);
        agent.key(&key).unwrap();

        mac.add_agent(&mut agent).unwrap();
        mac.secure_content(None).unwrap();

        let mut output = mac.encode(true).unwrap();
        let mut expected = get_test_vec("C53");

        // Remove probabilistic
        remove_probabilistic(
            &mut output,
            &mut expected,
            hex::decode("36f5afaf0bab5d43").unwrap(),
        );
        remove_probabilistic(
            &mut output,
            &mut expected,
            hex::decode("711ab0dc2fc4585dce27effa6781c8093eba906f227b6eb0").unwrap(),
        );

        assert_eq!(output, expected);

        // Verify MAC
        let mut verify = CoseMessage::new_mac();
        verify.set_bytes(mac.bytes);
        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(kid.clone()).unwrap()[0];
        key = get_key(kid, false);
        verify.set_agent_key(i, &key).unwrap();

        verify.decode(None, Some(i)).unwrap();
    }

    #[wasm_bindgen_test]
    fn c54() {
        let kid = b"018c0ae5-4d9b-471b-bfd6-eef314bc7037".to_vec();
        let ecdh_kid = b"bilbo.baggins@hobbiton.example".to_vec();
        let mut verify = CoseMessage::new_mac();
        verify.set_bytes(get_test_vec("C54"));
        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(kid.clone()).unwrap()[0];
        let key = get_key(kid, false);
        verify.set_agent_key(i, &key).unwrap();

        verify.decode(None, Some(i)).unwrap();

        let ecdh_i = verify.get_agent(ecdh_kid.clone()).unwrap()[0];
        let ecdh_key = get_key(ecdh_kid, false);

        verify.set_agent_key(ecdh_i, &ecdh_key).unwrap();

        verify.decode(None, Some(ecdh_i)).unwrap();

        verify.payload = b"This is not the content.".to_vec();
        assert!(verify.decode(None, Some(i)).is_err());
        assert!(verify.decode(None, Some(ecdh_i)).is_err());
    }

    #[wasm_bindgen_test]
    fn prod_c54() {
        let kid = b"018c0ae5-4d9b-471b-bfd6-eef314bc7037".to_vec();
        let ecdh_kid = b"bilbo.baggins@hobbiton.example".to_vec();
        let payload = b"This is the content.".to_vec();
        let mut mac = CoseMessage::new_mac();
        mac.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::HMAC_256_256, true, false);
        mac.set_header(header);

        let mut agent = agent::CoseAgent::new();
        header = headers::CoseHeader::new();
        header.set_alg(algs::ECDH_ES_A128KW, true, false);

        let mut ecdh_key = get_key(ecdh_kid.clone(), true);

        agent.set_header(header);
        agent.key(&ecdh_key).unwrap();

        let mut eph_key = keys::CoseKey::new();
        eph_key.set_kty(Some(keys::EC2));
        eph_key.set_crv(Some(keys::P_521));
        eph_key.set_x(Some(hex::decode("0018806d3bfca34308d189673142fed543ba23d990135ed65cce19c9d0fa674e828c662260754c59ccd25e727350cc106450c5f8b60151bfe9f1c012e072e290b502").unwrap()));
        eph_key.set_y_parity(Some(true));
        eph_key.set_d(Some(hex::decode("0127c20c9f565bb6ecd61898b2dea77db63ff54d20140348a274d059c17bdb2a07378b08cdee5bb9f676722c01e2607481d38e22aa41e9d205fb8759af78a711f7c4").unwrap()));

        agent.ephemeral_key(&eph_key, false, false);

        agent
            .header
            .set_kid(b"bilbo.baggins@hobbiton.example".to_vec(), false, false);

        mac.add_agent(&mut agent).unwrap();

        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::A256KW, false, false);
        header.set_kid(kid.clone(), false, false);

        let mut key = get_key(kid.clone(), false);

        agent = agent::CoseAgent::new();
        agent.set_header(header);
        agent.key(&key).unwrap();
        mac.add_agent(&mut agent).unwrap();

        mac.secure_content(None).unwrap();

        let mut output = mac.encode(true).unwrap();
        let mut expected = get_test_vec("C54");

        // Remove probabilistic
        remove_probabilistic(
            &mut output,
            &mut expected,
            hex::decode("bf48235e809b5c42e995f2b7d5fa13620e7ed834e337f6aa43df161e49e9323e")
                .unwrap(),
        );
        remove_probabilistic(
            &mut output,
            &mut expected,
            hex::decode(
                "339bc4f79984cdc6b3e6ce5f315a4c7d2b0ac466fcea69e8c07dfbca5bb1f661bc5f8e0df9e3eff5",
            )
            .unwrap(),
        );
        remove_probabilistic(
            &mut output,
            &mut expected,
            hex::decode(
                "0b2c7cfce04e98276342d6476a7723c090dfdd15f9a518e7736549e998370695e6d6a83b4ae507bb",
            )
            .unwrap(),
        );

        // Remove ephemeral key, different key used
        remove_probabilistic(
            &mut output,
            &mut expected,
            hex::decode(
                "0043b12669acac3fd27898ffba0bcd2e6c366d53bc4db71f909a759304acfb5e18cdc7ba0b13ff8c7636271a6924b1ac63c02688075b55ef2d613574e7dc242f79c3",
            )
            .unwrap(),
        );
        assert_eq!(output, expected);

        // Verify MAC
        let mut verify = CoseMessage::new_mac();
        verify.set_bytes(mac.bytes);
        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(kid.clone()).unwrap()[0];
        key = get_key(kid, false);
        verify.set_agent_key(i, &key).unwrap();

        verify.decode(None, Some(i)).unwrap();

        let i2 = verify.get_agent(ecdh_kid.clone()).unwrap()[0];
        ecdh_key = get_key(ecdh_kid, false);

        verify.set_agent_key(i2, &ecdh_key).unwrap();

        verify.decode(None, Some(i2)).unwrap();
    }

    #[wasm_bindgen_test]
    fn c61() {
        let mut verify = CoseMessage::new_mac();
        verify.set_bytes(get_test_vec("C61"));
        verify.init_decoder(None).unwrap();
        let key = get_key(b"our-secret".to_vec(), false);
        verify.key(&key).unwrap();
        verify.decode(None, None).unwrap();

        verify.payload = b"This is not the content.".to_vec();
        assert!(verify.decode(None, None).is_err());
    }

    #[wasm_bindgen_test]
    fn prod_c61() {
        let payload = b"This is the content.".to_vec();
        let mut mac = CoseMessage::new_mac();
        mac.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::AES_MAC_256_64, true, false);

        let mut key = get_key(b"our-secret".to_vec(), false);

        mac.set_header(header);
        mac.key(&key).unwrap();

        mac.secure_content(None).unwrap();

        let bytes = mac.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C61"));

        // Verify MAC
        let mut verify = CoseMessage::new_mac();
        verify.set_bytes(mac.bytes);
        verify.init_decoder(None).unwrap();
        key = get_key(b"our-secret".to_vec(), false);
        verify.key(&key).unwrap();
        verify.decode(None, None).unwrap();
    }

    #[wasm_bindgen_test]
    fn rsa_pss_01() {
        let kid = b"meriadoc.brandybuck@rsa.example".to_vec();
        let mut verify = CoseMessage::new_sign();
        verify.set_bytes(get_test_vec("RSA_PSS_01"));

        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(kid.clone()).unwrap()[0];
        let key = get_key(kid, true);

        verify.set_agent_key(i, &key).unwrap();

        verify.decode(None, Some(i)).unwrap();

        verify.payload = b"This is not the content.".to_vec();
        assert!(verify.decode(None, Some(i)).is_err());
    }

    #[wasm_bindgen_test]
    fn prod_rsa_pss_01() {
        let msg = b"This is the content.".to_vec();
        let kid = b"meriadoc.brandybuck@rsa.example".to_vec();
        let mut sign = CoseMessage::new_sign();

        let mut header = headers::CoseHeader::new();
        header.set_content_type(0, true, false);
        sign.set_header(header);
        sign.set_payload(msg);

        let mut agent = agent::CoseAgent::new();
        let mut agent_h = headers::CoseHeader::new();
        agent_h.set_alg(algs::PS256, true, false);
        agent_h.set_kid(kid.clone(), false, false);
        agent.set_header(agent_h);

        let mut key = get_key(kid.clone(), false);
        agent.key(&key).unwrap();

        sign.add_agent(&mut agent).unwrap();

        sign.secure_content(None).unwrap();

        let mut output = sign.encode(true).unwrap();
        let mut expected = get_test_vec("RSA_PSS_01");

        // Remove probabilistic
        remove_probabilistic(
            &mut output,
            &mut expected,
            hex::decode("3AD4027074989995F25E167F99C9B4096FDC5C242D438D30382AE7B30F83C88D5B5EBECB64D2256D58D3CCE5C47D343BFA532B117C2D04DF3FB20679A99CF3555A7DAE6098BD123B0F3441A1E50E897CBAA1B17CE171EBAB20AE2E10F16D6EE918D37AF102175979BE65EBCEDEB47519346EA3ED6D13B5741BC63742AE31342B10B46FE93F39B55FDD6E32128FD8B476FED88F671F304D0943D2C7A33BCE48DF08E1F890CF5ACDA3EF46DA21981C3A687CFFF85EEB276A98612F38D6EE63644859D66A9AD49939EA290F7A9FDFED9AF1246930F522CB8C6909567DCBE2729716CB18A31E6F231DB3D69A7A432AA3D6FA1DEF9C9659616BEB626F158378E0FBDD")
                .unwrap(),
        );

        assert_eq!(output, expected);

        // Verify
        let mut verify = CoseMessage::new_sign();
        verify.set_bytes(sign.bytes);

        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(kid.clone()).unwrap()[0];
        key = get_key(kid, true);

        verify.set_agent_key(i, &key).unwrap();

        verify.decode(None, Some(i)).unwrap();
    }

    #[wasm_bindgen_test]
    fn rsa_oaep_01() {
        let msg = b"This is the content.".to_vec();
        let kid = b"meriadoc.brandybuck@rsa.example".to_vec();
        let mut dec = CoseMessage::new_encrypt();
        dec.set_bytes(get_test_vec("RSA_OAEP_01"));
        dec.init_decoder(None).unwrap();
        let i = dec.get_agent(kid.clone()).unwrap()[0];
        let key = get_key(kid, false);
        dec.set_agent_key(i, &key).unwrap();

        assert_eq!(dec.decode(None, Some(i)).unwrap(), msg);
    }

    #[wasm_bindgen_test]
    fn prod_rsa_oaep_01() {
        use crate::agent;
        use crate::algs;
        use crate::headers;

        let msg = b"This is the content.".to_vec();
        let kid = b"meriadoc.brandybuck@rsa.example".to_vec();
        let mut enc = CoseMessage::new_encrypt();
        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::A128GCM, true, false);
        header.set_iv(
            vec![217, 122, 179, 165, 199, 45, 47, 13, 126, 95, 141, 94],
            false,
            false,
        );
        enc.set_header(header);
        enc.set_payload(msg);

        let mut agent = agent::CoseAgent::new();
        let mut agent_h = headers::CoseHeader::new();
        agent_h.set_alg(algs::RSA_OAEP_1, false, false);
        agent_h.set_kid(kid.clone(), false, false);
        agent.set_header(agent_h);

        let mut key = get_key(kid.clone(), true);
        agent.key(&key).unwrap();

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(None).unwrap();

        let mut output = enc.encode(true).unwrap();
        let mut expected = get_test_vec("RSA_OAEP_01");

        // Remove probabilistic
        remove_probabilistic(
            &mut output,
            &mut expected,
            hex::decode("613C8B53A5BBCD3A79F1314C668CB9EEFD362C1A78FE58AC2F7650B9F42284DEDDF6201C")
                .unwrap(),
        );
        remove_probabilistic(
            &mut output,
            &mut expected,
            hex::decode("7994141368C5FE18D3C75C296D84B31ED1BD0B9DCDB2E9C3BBDF4A199124D03E5171E09BF90099396C346FA62D2C2E54741169FB2FCA00ABE726CE0C4F55221E7A63001D39C2026EEE8AF9D3B2E8E97084C633470E32974D65C1E046A81319F8D04316710DA060F5F1A2AD304A220B7E9B11F86B09C1689935039519F368AD6CD6E0154487E923C0DE431AEA6425774736FDEDE666F248A136B3A08F63208CEAFACDE9F61E4CFF8AC30A61A0E024B28B7B4B0F77C2547C5652F07EF761A75A4193B989FA5C35E6A9297CD6895228C8E5B2559A9B7DD997753CBAEA6848337E200FF0F8042AA58B75839F79FFEF3C3A7F4AB9DE545A7B0646DF99908F2C8A80F4")
                .unwrap(),
        );
        assert_eq!(output, expected);

        // Decrypt
        let msg = b"This is the content.".to_vec();
        let mut dec = CoseMessage::new_encrypt();
        dec.set_bytes(enc.bytes);
        dec.init_decoder(None).unwrap();
        let i = dec.get_agent(kid.clone()).unwrap()[0];
        key = get_key(kid, false);
        dec.set_agent_key(i, &key).unwrap();

        assert_eq!(dec.decode(None, Some(i)).unwrap(), msg);
    }
}
