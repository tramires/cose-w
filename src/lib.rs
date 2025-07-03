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

        let key = get_key(kid, false);

        let mut agent = agent::CoseAgent::new();
        agent.set_header(header);
        agent.key(&key).unwrap();

        sign.add_agent(&mut agent).unwrap();
        sign.secure_content(None).unwrap();

        let bytes = sign.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C11"));
    }

    #[wasm_bindgen_test]
    fn c12() {
        let kid = b"11".to_vec();
        let mut verify = CoseMessage::new_sign();
        verify.set_bytes(get_test_vec("C12"));
        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(kid.clone()).unwrap()[0];
        let key = get_key(kid, true);
        verify.set_agent_key(i, &key).unwrap();
        verify.decode(None, Some(i)).unwrap();
        // 2nd signer uses ES512 (Not Implemented)
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

        let key = get_key(kid.clone(), false);

        let mut agent = agent::CoseAgent::new();
        agent.set_header(header);
        agent.key(&key).unwrap();

        sign.add_agent(&mut agent).unwrap();
        sign.secure_content(None).unwrap();

        let mut counter = agent::CoseAgent::new_counter_sig();

        let mut header = headers::CoseHeader::new();
        header.set_kid(kid, false, false);
        header.set_alg(algs::ES256, true, false);

        counter.set_header(header);
        counter.key(&key).unwrap();

        sign.counter_sig(None, &mut counter, None).unwrap();
        sign.add_counter_sig(counter, None).unwrap();

        let bytes = sign.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C13"));
    }

    #[wasm_bindgen_test]
    fn c21() {
        let mut verify = CoseMessage::new_sign();
        verify.set_bytes(get_test_vec("C21"));
        verify.init_decoder(None).unwrap();

        let key = get_key(verify.header.kid.clone().unwrap(), true);

        verify.key(&key).unwrap();
        verify.decode(None, None).unwrap();
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

        let key = get_key(kid, false);

        sign.key(&key).unwrap();

        sign.secure_content(None).unwrap();

        let bytes = sign.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C21"));
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

        let key = get_key(kid.clone(), true);

        let mut agent = agent::CoseAgent::new();
        header = headers::CoseHeader::new();
        header.set_alg(algs::ECDH_ES_HKDF_256, true, false);

        agent.set_header(header);
        agent.key(&key).unwrap();

        let mut key1 = get_key(b"peregrin.took@tuckborough.example".to_vec(), false);
        key1.set_y_parity(Some(true));

        agent.ephemeral_key(key1, false, false);
        agent.header.set_kid(kid, false, false);

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(None).unwrap();

        let bytes = enc.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C31"));
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

        let key = get_key(kid.clone(), false);

        let mut agent = agent::CoseAgent::new();
        header = headers::CoseHeader::new();
        header.set_alg(algs::DIRECT_HKDF_SHA_256, true, false);
        header.set_salt(salt, false, false);
        header.set_kid(kid, false, false);
        header.set_party_identity(b"lighting-client".to_vec(), false, false, true, false);
        header.set_party_identity(b"lighting-server".to_vec(), false, false, false, false);
        header.set_pub_other(Some(b"Encryption Example 02".to_vec()));

        agent.set_header(header);
        agent.key(&key).unwrap();

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(None).unwrap();

        let bytes = enc.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C32"));
    }

    #[wasm_bindgen_test]
    fn c33() {
        let mut dec = CoseMessage::new_encrypt();
        dec.set_bytes(get_test_vec("C33"));
        dec.init_decoder(None).unwrap();

        let key = get_key(dec.agents[0].header.kid.clone().unwrap(), false);

        dec.set_agent_key(0, &key).unwrap();
        let decoded = dec.decode(None, Some(0)).unwrap();
        assert_eq!(decoded, b"This is the content.".to_vec());
        // Counter signature uses ES512 (Not implemented)
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

        let key = get_key(kid.clone(), true);

        let mut agent = agent::CoseAgent::new();
        header = headers::CoseHeader::new();
        header.set_alg(algs::ECDH_SS_A128KW, true, false);

        agent.set_header(header);
        agent.key(&key).unwrap();

        let key1 = get_key(b"peregrin.took@tuckborough.example".to_vec(), false);

        agent.header.set_static_kid(
            b"peregrin.took@tuckborough.example".to_vec(),
            key1,
            false,
            false,
        );
        agent.header.set_kid(kid.clone(), false, false);
        agent.header.set_party_nonce(vec![1, 1], false, false, true);

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(Some(aad)).unwrap();

        let mut output = enc.encode(true).unwrap();
        let mut expected = get_test_vec("C34");

        // Remove ciphertext and cek (probabilistic) for comparison
        let mut prob = vec![
            100, 248, 77, 145, 59, 166, 10, 118, 7, 10, 154, 72, 242, 110, 151, 232, 99, 226, 133,
            41, 216, 245, 51, 94, 95, 1, 101, 238, 233, 118, 180, 165, 246, 198, 240, 157,
        ];

        let mut index = expected
            .windows(prob.len())
            .position(|window| window == &prob)
            .unwrap();

        expected.drain(index..index + prob.len());
        output.drain(index..index + prob.len());

        prob = vec![
            65, 224, 215, 111, 87, 157, 189, 13, 147, 106, 102, 45, 84, 216, 88, 32, 55, 222, 46,
            54, 111, 222, 28, 98,
        ];

        index = expected
            .windows(prob.len())
            .position(|window| window == &prob)
            .unwrap();

        expected.drain(index..index + prob.len());
        output.drain(index..index + prob.len());

        assert_eq!(output, expected);
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

        let key = get_key(b"our-secret2".to_vec(), false);

        enc.key(&key).unwrap();
        enc.secure_content(None).unwrap();

        let bytes = enc.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C41"));
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
        let mut sign = CoseMessage::new_encrypt();
        sign.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::AES_CCM_16_64_128, true, false);
        header.set_partial_iv(vec![97, 167], false, false);
        sign.set_header(header);

        let mut key = get_key(b"our-secret2".to_vec(), false);
        key.set_base_iv(Some(vec![137, 245, 47, 101, 161, 197, 128, 147]));

        sign.key(&key).unwrap();
        sign.secure_content(None).unwrap();

        let bytes = sign.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C42"));
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

        let key = get_key(b"our-secret".to_vec(), false);

        let mut agent = agent::CoseAgent::new();
        agent.set_header(header);
        agent.key(&key).unwrap();

        mac.add_agent(&mut agent).unwrap();
        mac.secure_content(None).unwrap();

        let bytes = mac.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C51"));
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

        let key = get_key(kid.clone(), true);

        let mut agent = agent::CoseAgent::new();
        header = headers::CoseHeader::new();
        header.set_alg(algs::ECDH_SS_HKDF_256, true, false);

        let key1 = get_key(b"peregrin.took@tuckborough.example".to_vec(), false);

        header.set_static_kid(
            b"peregrin.took@tuckborough.example".to_vec(),
            key1,
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

        let key = get_key(kid, false);

        let mut agent = agent::CoseAgent::new();
        agent.set_header(header);
        agent.key(&key).unwrap();

        mac.add_agent(&mut agent).unwrap();
        mac.secure_content(None).unwrap();

        let mut bytes = mac.encode(true).unwrap();
        let mut expected = get_test_vec("C53");

        // Remove probabilistic
        let mut prob = vec![54, 245, 175, 175, 11, 171, 93, 67];
        let mut index = expected
            .windows(prob.len())
            .position(|window| window == &prob)
            .unwrap();

        expected.drain(index..index + prob.len());
        bytes.drain(index..index + prob.len());

        prob = vec![
            113, 26, 176, 220, 47, 196, 88, 93, 206, 39, 239, 250, 103, 129, 200, 9, 62, 186, 144,
            111, 34, 123, 110, 176,
        ];

        index = expected
            .windows(prob.len())
            .position(|window| window == &prob)
            .unwrap();

        expected.drain(index..index + prob.len());
        bytes.drain(index..index + prob.len());

        assert_eq!(bytes, expected);
    }

    #[wasm_bindgen_test]
    fn c54() {
        let kid = b"018c0ae5-4d9b-471b-bfd6-eef314bc7037".to_vec();
        let mut verify = CoseMessage::new_mac();
        verify.set_bytes(get_test_vec("C54"));
        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(kid.clone()).unwrap()[0];
        let key = get_key(kid, false);
        verify.set_agent_key(i, &key).unwrap();

        verify.decode(None, Some(i)).unwrap();
        //2nd recipient uses ES512  (Not implemented)
    }

    #[wasm_bindgen_test]
    fn c61() {
        let mut verify = CoseMessage::new_mac();
        verify.set_bytes(get_test_vec("C61"));
        verify.init_decoder(None).unwrap();
        let key = get_key(b"our-secret".to_vec(), false);
        verify.key(&key).unwrap();
        verify.decode(None, None).unwrap();
    }

    #[wasm_bindgen_test]
    fn prod_c61() {
        let payload = b"This is the content.".to_vec();
        let mut mac = CoseMessage::new_mac();
        mac.set_payload(payload);

        let mut header = headers::CoseHeader::new();
        header.set_alg(algs::AES_MAC_256_64, true, false);

        let key = get_key(b"our-secret".to_vec(), false);

        mac.set_header(header);
        mac.key(&key).unwrap();

        mac.secure_content(None).unwrap();

        let bytes = mac.encode(true).unwrap();
        assert_eq!(bytes, get_test_vec("C61"));
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

        let key = get_key(kid, false);
        agent.key(&key).unwrap();

        sign.add_agent(&mut agent).unwrap();

        sign.secure_content(None).unwrap();

        let mut output = sign.encode(true).unwrap();
        let mut expected = get_test_vec("RSA_PSS_01");

        // Remove probabilistic
        let prob = vec![
            58, 212, 2, 112, 116, 152, 153, 149, 242, 94, 22, 127, 153, 201, 180, 9, 111, 220, 92,
            36, 45, 67, 141, 48, 56, 42, 231, 179, 15, 131, 200, 141, 91, 94, 190, 203, 100, 210,
            37, 109, 88, 211, 204, 229, 196, 125, 52, 59, 250, 83, 43, 17, 124, 45, 4, 223, 63,
            178, 6, 121, 169, 156, 243, 85, 90, 125, 174, 96, 152, 189, 18, 59, 15, 52, 65, 161,
            229, 14, 137, 124, 186, 161, 177, 124, 225, 113, 235, 171, 32, 174, 46, 16, 241, 109,
            110, 233, 24, 211, 122, 241, 2, 23, 89, 121, 190, 101, 235, 206, 222, 180, 117, 25, 52,
            110, 163, 237, 109, 19, 181, 116, 27, 198, 55, 66, 174, 49, 52, 43, 16, 180, 111, 233,
            63, 57, 181, 95, 221, 110, 50, 18, 143, 216, 180, 118, 254, 216, 143, 103, 31, 48, 77,
            9, 67, 210, 199, 163, 59, 206, 72, 223, 8, 225, 248, 144, 207, 90, 205, 163, 239, 70,
            218, 33, 152, 28, 58, 104, 124, 255, 248, 94, 235, 39, 106, 152, 97, 47, 56, 214, 238,
            99, 100, 72, 89, 214, 106, 154, 212, 153, 57, 234, 41, 15, 122, 159, 223, 237, 154,
            241, 36, 105, 48, 245, 34, 203, 140, 105, 9, 86, 125, 203, 226, 114, 151, 22, 203, 24,
            163, 30, 111, 35, 29, 179, 214, 154, 122, 67, 42, 163, 214, 250, 29, 239, 156, 150, 89,
            97, 107, 235, 98, 111, 21, 131, 120, 224, 251, 221,
        ];
        let index = expected
            .windows(prob.len())
            .position(|window| window == &prob)
            .unwrap();

        expected.drain(index..index + prob.len());
        output.drain(index..index + prob.len());

        assert_eq!(output, expected);
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

        let key = get_key(kid, true);
        agent.key(&key).unwrap();

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(None).unwrap();

        let mut output = enc.encode(true).unwrap();
        let mut expected = get_test_vec("RSA_OAEP_01");

        // Remove probabilistic
        let mut prob = vec![
            97, 60, 139, 83, 165, 187, 205, 58, 121, 241, 49, 76, 102, 140, 185, 238, 253, 54, 44,
            26, 120, 254, 88, 172, 47, 118, 80, 185, 244, 34, 132, 222, 221, 246, 32, 28,
        ];
        let mut index = expected
            .windows(prob.len())
            .position(|window| window == &prob)
            .unwrap();

        expected.drain(index..index + prob.len());
        output.drain(index..index + prob.len());

        prob = vec![
            121, 148, 20, 19, 104, 197, 254, 24, 211, 199, 92, 41, 109, 132, 179, 30, 209, 189, 11,
            157, 205, 178, 233, 195, 187, 223, 74, 25, 145, 36, 208, 62, 81, 113, 224, 155, 249, 0,
            153, 57, 108, 52, 111, 166, 45, 44, 46, 84, 116, 17, 105, 251, 47, 202, 0, 171, 231,
            38, 206, 12, 79, 85, 34, 30, 122, 99, 0, 29, 57, 194, 2, 110, 238, 138, 249, 211, 178,
            232, 233, 112, 132, 198, 51, 71, 14, 50, 151, 77, 101, 193, 224, 70, 168, 19, 25, 248,
            208, 67, 22, 113, 13, 160, 96, 245, 241, 162, 173, 48, 74, 34, 11, 126, 155, 17, 248,
            107, 9, 193, 104, 153, 53, 3, 149, 25, 243, 104, 173, 108, 214, 224, 21, 68, 135, 233,
            35, 192, 222, 67, 26, 234, 100, 37, 119, 71, 54, 253, 237, 230, 102, 242, 72, 161, 54,
            179, 160, 143, 99, 32, 140, 234, 250, 205, 233, 246, 30, 76, 255, 138, 195, 10, 97,
            160, 224, 36, 178, 139, 123, 75, 15, 119, 194, 84, 124, 86, 82, 240, 126, 247, 97, 167,
            90, 65, 147, 185, 137, 250, 92, 53, 230, 169, 41, 124, 214, 137, 82, 40, 200, 229, 178,
            85, 154, 155, 125, 217, 151, 117, 60, 186, 234, 104, 72, 51, 126, 32, 15, 240, 248, 4,
            42, 165, 139, 117, 131, 159, 121, 255, 239, 60, 58, 127, 74, 185, 222, 84, 90, 123, 6,
            70, 223, 153, 144, 143, 44, 138, 128, 244,
        ];

        index = expected
            .windows(prob.len())
            .position(|window| window == &prob)
            .unwrap();

        expected.drain(index..index + prob.len());
        output.drain(index..index + prob.len());

        assert_eq!(output, expected);
    }
}
