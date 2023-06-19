# CoseEncrypt documentation

Module to encode/decode cose-encrypt0 and cose-encrypt messages.

## Getters

- `header`: CoseHeader of the message.
- `bytes`: Final encoded message.
- `payload`: Payload of the message.
- `counters_len`: Number of counter signers.

When decoding a COSE message, after the function `init_decoding`, all the COSE message parameters will be accessible by the previously listed getters.

## Methods 

- `set_bytes(bytes: Vec<u8>)`: Sets the COSE message bytes to decode.
- `set_header(header: CoseHeader)`: Sets the COSE header.
- `set_payload(payload: Vec<u8>)`: Sets the payload to be encoded.
- `key(key: keys::CoseKey)`: Sets key to be used in case of cose-encrypt0 message.
- `set_key(key: keys::CoseKey)`: Sets key to be used in case of cose-encrypt0 message.
- `gen_ciphertext(external_aad: Option<Vec<u8>>)`: Generate ciphertext with optional external AAD.
- `encode(ciphertext: bool)`: Encode the final message, ciphertext parameter defines if the ciphertext is to be included in the COSE encoded message.
- `init_decoder(ciphertext: Option<Vec<u8>>)`: Initial decoding of the COSE message to accesss the message atributes to further validate/decode the message, the parameter ciphertext needs to be provided if its not included in the encoded COSE message.
- `decode(external_aad: Option<Vec<u8>>, recipient: Option<usize>)`: Final decode of the COSE message, with the option to include external AAD. If cose-encrypt0 type message, the recipient parameter can be null, else if cose-encrypt type, a recipient index must be provided and the respective recipient key must be set.

### Recipients:

Methods for when using cose-encrypt message type:

- `recipient_header(i: usize)`: Get the recipient header.
- `add_recipient(recipient: &mut CoseAgent)`: Add recipient to the message.
- `get_recipient(kid: Vec<u8>)`: Get recipients with the provided key ID.
- `pub fn add_recipient_key(index: usize, cose_key: CoseKey)`: Adds a COSE key to a recipient.

### Counter Signers:

#### TODO 

Methods for when including counter signatures in the message:

- `counter_header(i: usize)`: 
- `counter(kid: Vec<u8>)`: 
- `add_counter_key(i: usize, key: &keys::CoseKey)`: 
- `counter_sig(external_aad: Option<Vec<u8>>, counter: &mut CoseAgent)`:
- `get_to_sign(external_aad: Option<Vec<u8>>, counter: &mut CoseAgent)`: 
- `get_to_verify`: 
- `counters_verify`:  
- `add_counter_sig(&mut self, counter: CoseAgent)`: 

# Examples

## cose-encrypt0

Encode/decode cose-encrypt0.

### Encode cose-encrypt0
```js
// Message to encrypt, "This is the content."
let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare cose-key
let key = new CoseKey();
key.set_kty(Kty.symmetric);
key.set_alg(Alg.chacha20);
key.set_k(Buffer.from('849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188', 'hex'));
key.set_key_ops([KeyOp.encrypt]);

// Prepare cose-encrypt0 header
let header = new CoseHeader();
header.set_alg(Alg.chacha20, true, false);
header.set_iv(Buffer.from('89f52f65a1c580933b5261a7', 'hex'), true, false);

// Generate CoseEncrypt and encode the cose-encrypt0 final message
let mac = new CoseEncrypt();
mac.set_header(header);
mac.set_payload(msg);
mac.key(key);
mac.gen_ciphertext(null);
mac.encode(true);
```

### Decode cose-encrypt0
```js
// "This is the content."
let expected_msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare cose-key
let key = new CoseKey();
key.set_kty(Kty.symmetric);
key.set_alg(Alg.chacha20);
key.set_k(Buffer.from('849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188', 'hex'));
key.set_key_ops([KeyOp.decrypt]);

// Prepare CoseEncrypt with the cose-encrypt0 bytes
let dec = new CoseEncrypt();
dec.set_bytes(Buffer.from("d08352a2011818054c89f52f65a1c580933b5261a7a0582481c32c048134989007b3b5b932811ea410eeab15bd0de5d5ac5be03c84dce8c88871d6e9", "hex"));

// Init decoding and add key
dec.init_decoder(null);
dec.key(key);

// Decrypt and verify cose-encrypt0 message
let msg = dec.decode(null);
assert.deepEqual(new Buffer.from(msg).toString(), expected_msg.toString());
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
key2.set_alg(Alg.es256);
key2.set_crv(Crv.p_256);
key2.set_x(Buffer.from('98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280', 'hex'));
key2.set_y(Buffer.from('F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB', 'hex'));

// Prepare recipient 2 ephemeral ECDH cose-key
let eph_key2 = new CoseKey();
eph_key2.set_kty(Kty.ec2);
eph_key2.set_alg(Alg.es256);
eph_key2.set_crv(Crv.p_256);
eph_key2.set_x(Buffer.from('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', 'hex'));
eph_key2.set_d(Buffer.from('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex'));
eph_key2.set_key_ops([KeyOp.derive]);

// Prepare cose-encrypt header
let header = new CoseHeader();
header.set_alg(Alg.a256gcm, true, false);
header.set_iv(Buffer.from('89f52f65a1c580933b5261a7', 'hex'), true, false);

// Prepare CoseEncrypt
let enc = new CoseEncrypt();
enc.set_header(header);
enc.set_payload(msg);

// Add recipient 1
let recipient1 = new CoseAgent();
header = new CoseHeader();
header.set_alg(Alg.a128kw, true, false);
header.set_kid([0], false, false);
recipient1.set_header(header);
recipient1.key(key1);
enc.add_recipient(recipient1);

// Add recipient 2
let recipient2 = new CoseAgent();
header = new CoseHeader();
header.set_alg(Alg.ecdh_es_a128kw, true, false);
header.set_kid([1], false, false);
recipient2.set_header(header);
recipient2.key(key2);
recipient2.ephemeral_key(eph_key2, true, false);
enc.add_recipient(recipient2);

// Gen ciphertext and encode
enc.gen_ciphertext(null);
enc.encode(true);
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
key2.set_alg(Alg.es256);
key2.set_crv(Crv.p_256);
key2.set_d(Buffer.from('02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3', 'hex'));
key2.set_key_ops([KeyOp.derive]);

// Prepare CoseEncrypt with the cose-encrypt bytes
let dec = new CoseEncrypt();
dec.set_bytes(Buffer.from("d8608451a20103054c89f52f65a1c580933b5261a7a05824b405d0fdca0bc1cad073275e402933c19e198d4d8b69c6cbceef55c231becbe8a7d5604e828343a10122a10441005828bc703be59088671a557a928670186af85da2157a7b1d23cf0c0c53ee89c7819028eb343c29545a8f835832a201381c20a5010203262001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff048107a1044101582813e5bf1bc51a20fed5b199dd0d8cbeaaf899ab272a52794b0e46a94f66a413cb21c7c15d632c7169", "hex"));

// Init decoding
dec.init_decoder(null);

// Get recipient 1 and decrypt 
let recipient1_i = dec.get_recipient([0])[0];
let info = dec.recipient_header(recipient1_i);
dec.add_recipient_key(recipient1_i, key1);
let msg = dec.decode(null, recipient1_i);
assert.deepEqual(Buffer.from(msg).toString(), expected_msg.toString());


// Get recipient 2 and decrypt
let recipient2_i = dec.get_recipient([1])[0];
dec.add_recipient_key(recipient2_i, key2);
msg = dec.decode(null, recipient2_i);
assert.deepEqual(Buffer.from(msg).toString(), expected_msg.toString());
```
