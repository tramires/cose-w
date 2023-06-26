# CoseSign documentation

Module to encode/decode cose-sign1 and cose-sign messages.

## Getters

- `header`: CoseHeader of the message.
- `bytes`: Final encoded message.
- `payload`: Payload of the message.
- `counters_len`: Number of counter signers.

When decoding a COSE message, after the function `init_decoding`, all the COSE message parameters will be accessible by the previously listed getters.

## Constructors:
- `new_sign()`: Creates a COSE sign message type instance (cose-sign1 and cose-sign),
- `new_encrypt()`: Creates a COSE encrypt message type instance (cose-encrypt0 and cose-encrypt),
- `new_mac()`: Creates a COSE MAC message type instance (cose-mac0 and cose-mac),

## Methods 


- `set_bytes(bytes: Vec<u8>)`: Sets the COSE message bytes to decode.
- `set_header(header: CoseHeader)`: Sets the COSE header.
- `set_payload(payload: Vec<u8>)`: Sets the payload to be encoded.
- `key(key: keys::CoseKey)`: Sets key to be used in case of cose-sign1 message.
- `set_key(key: keys::CoseKey)`: Sets key to be used in case of cose-sign1 message.
- `gen_signature(external_aad: Option<Vec<u8>>)`: Generate signature with optional external AAD.
- `encode(payload: bool)`: Encode the final message, payload parameter defines if the payload is to be included in the COSE encoded message.
- `init_decoder(payload: Option<Vec<u8>>)`: Initial decoding of the COSE message to accesss the message atributes to further validate/decode the message, the parameter payload needs to be provided if its not included in the encoded COSE message.
- `decode(external_aad: Option<Vec<u8>>, signer: Option<usize>)`: Final decode of the COSE message, with the option to include external AAD. If cose-sign1 type message, the signer parameter can be null, else if cose-sign type, a signer index must be provided and the respective signer key must be set.

### Signers:

Methods for when using cose-sign message type:

- `agent_header(i: usize)`: Get the signer header.
- `add_agent(agent: &mut CoseAgent)`: Add signer to the message.
- `get_agent(kid: Vec<u8>)`: Get signers with the provided key ID.
- `pub fn add_agent_key(index: usize, cose_key: CoseKey)`: Adds a COSE key to a signer.

### Counter Signers:

Methods for when including counter signatures in the message:

- `counter_header(i: usize)`: Get counter header.
- `counter(kid: Vec<u8>)`: get array positions of the message counters with respective KID.
- `add_counter_key(i: usize, key: &keys::CoseKey)`: Adds counter signer COSE key. 
- `counter_sig(external_aad: Option<Vec<u8>>, counter: &mut CoseAgent)`: Generate Counter Signature.
- `counters_verify(external_aad: Option<Vec<u8>>, counter: usize)`: Verify Counter Signature.
- `get_to_sign(external_aad: Option<Vec<u8>>, counter: &mut CoseAgent)`: Get content to sign externaly to the module.
- `get_to_verify(external_aad: Option<Vec<u8>>, counter: &mut CoseAgent)`:  Get  content to verify externaly to the module.
- `add_counter_sig(counter: CoseAgent)`: Add counter signature to the COSE message.

# Examples 

Examples of single recipient messages (cose-sign1, cose-mac0 and cose-encrypt0) can be seen in [here](README.md).

## cose-sign

Encode/decode cose-sign.

### Encode cose-sign 
```js
 // Message to sign, "This is the content."
let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare signer 1 cose-key
let key1 = new CoseKey();
key1.set_kty(Kty.ec2);
key1.set_alg(Alg.es256);
key1.set_crv(Crv.p_256);
key1.set_d(Buffer.from('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex'));
key1.set_key_ops([KeyOp.sign]);

// Prepare signer2 cose-key
let key2 = new CoseKey();
key2.set_kty(Kty.ec2);
key2.set_alg(Alg.es256);
key2.set_crv(Crv.p_256);
key2.set_d(Buffer.from('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex'));
key2.set_key_ops([KeyOp.sign]);

// Prepare CoseSign
let sign = CoseMessage.new_sign();
sign.set_payload(msg);

// Add signer 1
let signer1 = new CoseAgent();
let header = new CoseHeader();
header.set_alg(Alg.es256, true, false);
header.set_kid([1], true, false);
signer1.set_header(header);
signer1.key(key1);
sign.add_agent(signer1);

// Add signer 2
let signer2 = new CoseAgent();
header = new CoseHeader();
header.set_alg(Alg.es256, true, false);
header.set_kid([2], true, false);
signer2.set_header(header);
signer2.key(key2);
sign.add_agent(signer2);

// Generate signature and encode cose-sign message
sign.secure_content(null);
let bytes = sign.encode(true);
```

### Decode cose-sign 
```js
// Prepare signer 1 cose-key
let key1 = new CoseKey();
key1.set_kty(Kty.ec2);
key1.set_alg(Alg.es256);
key1.set_crv(Crv.p_256);
key1.set_x(Buffer.from('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', 'hex'));
key1.set_y(Buffer.from('20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e', 'hex'));
key1.set_key_ops([KeyOp.verify]);

// Prepare signer2 cose-key
let key2 = new CoseKey();
key2.set_kty(Kty.ec2);
key2.set_alg(Alg.es256);
key2.set_crv(Crv.p_256);
key2.set_x(Buffer.from('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', 'hex'));
key2.set_y(Buffer.from('20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e', 'hex'));
key2.set_key_ops([KeyOp.verify]);

// Prepare CoseSign with the cose-sign bytes
let verify = CoseMessage.new_sign();
verify.set_bytes(Buffer.from("d8628440a054546869732069732074686520636f6e74656e742e828346a20126044101a058408d53d4fd916a66c7e93979c0d68938045b35902ab0ae880c

// Init decoding
verify.init_decoder(null);

// Get signer 1 and verify
let signer1_i = verify.get_agent([1])[0];
verify.add_agent_key(signer1_i, key1);
verify.decode(null, signer1_i);

// Get signer 2 and verify
let signer2_i = verify.get_agent([2])[0];
verify.add_agent_key(signer2_i, key2);
let payload = verify.decode(null, signer2_i);
```

## cose-encrypt

Encode/decode cose-encrypt.

### Encode cose-encrypt
```js
// Message to encrypt, "This is the content."
let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare recipient 1 cose-key
let key1 = new CoseKey();
key1.set_kty(Kty.symmetric);
key1.set_alg(Alg.a128kw);
key1.set_k(Buffer.from('849b57219dae48de646d07dbb533566e', 'hex'));
key1.set_key_ops([KeyOp.wrap]);

// Prepare recipient 2 cose-key
let key2 = new CoseKey();
key2.set_kty(Kty.ec2);
key2.set_crv(Crv.p_256);
key2.set_x(Buffer.from('98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280', 'hex'));
key2.set_y(Buffer.from('F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB', 'hex'));

// Prepare recipient 2 ephemeral ECDH cose-key
let eph_key2 = new CoseKey();
eph_key2.set_kty(Kty.ec2);
eph_key2.set_crv(Crv.p_256);
eph_key2.set_x(Buffer.from('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', 'hex'));
eph_key2.set_d(Buffer.from('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex'));
eph_key2.set_key_ops([KeyOp.derive]);

// Prepare cose-encrypt header
let header = new CoseHeader();
header.set_alg(Alg.a256gcm, true, false);
header.set_iv(Buffer.from('89f52f65a1c580933b5261a7', 'hex'), true, false);

// Prepare CoseEncrypt
let enc = CoseMessage.new_encrypt();
enc.set_header(header);
enc.set_payload(msg);

// Add recipient 1
let recipient1 = new CoseAgent();
header = new CoseHeader();
header.set_alg(Alg.a128kw, true, false);
header.set_kid([0], false, false);
recipient1.set_header(header);
recipient1.key(key1);
enc.add_agent(recipient1);

// Add recipient 2
let recipient2 = new CoseAgent();
header = new CoseHeader();
header.set_alg(Alg.ecdh_es_a128kw, true, false);
header.set_kid([1], false, false);
recipient2.set_header(header);
recipient2.key(key2);
recipient2.ephemeral_key(eph_key2, true, false);
enc.add_agent(recipient2);

// Gen ciphertext and encode
enc.secure_content(null);
let bytes = enc.encode(true);
```
### Decode cose-encrypt
```js
// Expected messsage to decrypt
let expected_msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare recipient 1 cose-key
let key1 = new CoseKey();
key1.set_kty(Kty.symmetric);
key1.set_alg(Alg.a128kw);
key1.set_k(Buffer.from('849b57219dae48de646d07dbb533566e', 'hex'));
key1.set_key_ops([KeyOp.unwrap]);

// Prepare recipient 2 cose-key
let key2 = new CoseKey();
key2.set_kty(Kty.ec2);
key2.set_crv(Crv.p_256);
key2.set_d(Buffer.from('02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3', 'hex'));
key2.set_key_ops([KeyOp.derive]);

// Prepare CoseEncrypt with the cose-encrypt bytes
let dec = CoseMessage.new_encrypt();
dec.set_bytes(Buffer.from("d8608451a20103054c89f52f65a1c580933b5261a7a05824b405d0fdca0bc1cad073275e402933c19e198d4d8b69c6cbceef55c231becbe8a7d5604e828343a

// Init decoding
dec.init_decoder(null);

// Get recipient 1 and decrypt
let recipient1_i = dec.get_agent([0])[0];
let info = dec.agent_header(recipient1_i);
dec.add_agent_key(recipient1_i, key1);
let msg = dec.decode(null, recipient1_i);
assert.deepEqual(Buffer.from(msg).toString(), expected_msg.toString());


// Get recipient 2 and decrypt
let recipient2_i = dec.get_agent([1])[0];
dec.add_agent_key(recipient2_i, key2);
msg = dec.decode(null, recipient2_i);
assert.deepEqual(Buffer.from(msg).toString(), expected_msg.toString());
```

## cose-mac

Encode/decode cose-mac.

### Encode cose-mac
```js
// Message to MAC, "This is the content."
let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare recipient 1 cose-key
let key1 = new CoseKey();
key1.set_kty(Kty.symmetric);
key1.set_alg(Alg.a128kw);
key1.set_k(Buffer.from('849b57219dae48de646d07dbb533566e', 'hex'));
key1.set_key_ops([KeyOp.wrap, KeyOp.unwrap]);

// Prepare recipient 2 cose-key
let key2 = new CoseKey();
key2.set_kty(Kty.ec2);
key2.set_crv(Crv.p_256);
key2.set_x(Buffer.from('98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280', 'hex'));
key2.set_y(Buffer.from('F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB', 'hex'));

// Prepare recipient 2 ephemeral ECDH cose-key
let eph_key2 = new CoseKey();
eph_key2.set_kty(Kty.ec2);
eph_key2.set_crv(Crv.p_256);
eph_key2.set_x(Buffer.from('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', 'hex'));
eph_key2.set_d(Buffer.from('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex'));
eph_key2.set_key_ops([KeyOp.derive]);

// Prepare cose-mac header
let header = new CoseHeader();
header.set_alg(Alg.aes_mac_256_128, true, false);
header.set_iv(Buffer.from('89f52f65a1c580933b5261a7', 'hex'), true, false);

// Prepare CoseMAC
let mac = CoseMessage.new_mac();
mac.set_header(header);
mac.set_payload(msg);

// Add recipient 1
let recipient1 = new CoseAgent();
header = new CoseHeader();
header.set_alg(Alg.a128kw, true, false);
header.set_kid(Buffer.from("3131", "hex"), false, false);
recipient1.set_header(header);
recipient1.key(key1);
mac.add_agent(recipient1);

// Add recipient 2
let recipient2 = new CoseAgent();
header = new CoseHeader();
header.set_alg(Alg.ecdh_es_a128kw, true, false);
header.set_kid(Buffer.from("3232", "hex"), false, false);
recipient2.set_header(header);
recipient2.key(key2);
recipient2.ephemeral_key(eph_key2, true, false);
mac.add_agent(recipient2);

// Generate tag and encode final message
mac.secure_content(null);
let bytes = mac.encode(true);
```
### Decode cose-mac
```js
// Prepare recipient 1 cose-key
let key1 = new CoseKey();
key1.set_kty(Kty.symmetric);
key1.set_alg(Alg.a128kw);
key1.set_k(Buffer.from('849b57219dae48de646d07dbb533566e', 'hex'));
key1.set_key_ops([KeyOp.unwrap]);

// Prepare recipient 2 cose-key
let key2 = new CoseKey();
key2.set_kty(Kty.ec2);
key2.set_crv(Crv.p_256);
key2.set_d(Buffer.from('02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3', 'hex'));
key2.set_key_ops([KeyOp.derive]);

// Prepare CoseMAC with the cose-mac bytes
let verify = CoseMessage.new_mac();
verify.set_bytes(Buffer.from("d8618552a201181a054c89f52f65a1c580933b5261a7a054546869732069732074686520636f6e74656e742e50294e0160dbb25ee48703e918c6051f8882

// Init decoding
verify.init_decoder(null);

// Get recipient 1 and verify tag
let recipient1_i = verify.get_agent(Buffer.from("3131", "hex"))[0];
verify.add_agent_key(recipient1_i, key1);
verify.decode(null, recipient1_i);

// Get recipient 2 and verify tag
let recipient2_i = verify.get_agent(Buffer.from("3232", "hex"))[0];
verify.add_agent_key(recipient2_i, key2);
let payload = verify.decode(null, recipient2_i);
```
