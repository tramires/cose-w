# CoseMAC documentation

Module to encode/decode cose-mac0 and cose-mac messages.

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
- `key(key: keys::CoseKey)`: Sets key to be used in case of cose-mac0 message.
- `set_key(key: keys::CoseKey)`: Sets key to be used in case of cose-mac0 message.
- `gen_tag(external_aad: Option<Vec<u8>>)`: Generate tag with optional external AAD.
- `encode(payload: bool)`: Encode the final message, payload parameter defines if the payload is to be included in the COSE encoded message.
- `init_decoder(payload: Option<Vec<u8>>)`: Initial decoding of the COSE message to accesss the message atributes to further validate/decode the message, the parameter payload needs to be provided if its not included in the encoded COSE message.
- `decode(external_aad: Option<Vec<u8>>, recipient: Option<usize>)`: Final decode of the COSE message, with the option to include external AAD. If cose-mac0 type message, the recipient parameter can be null, else if cose-mac type, a recipient index must be provided and the respective recipient key must be set.

### Recipients:

Methods for when using cose-mac message type:

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

## cose-mac0

Encode/decode cose-mac0.

### Encode cose-mac0
```js
// Message to MAC, "This is the content."
let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare cose-key
let key = new CoseKey();
key.set_kty(Kty.symmetric);
key.set_alg(Alg.aes_mac_256_128);
key.set_k(Buffer.from('849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188', 'hex'));
key.set_key_ops([KeyOp.mac]);

// Prepare cose-mac0 header
let header = new CoseHeader();
header.set_alg(Alg.aes_mac_256_128, true, false);

// Generate CoseMAC and encode the cose-mac0 final message
let mac = new CoseMAC();
mac.set_header(header);
mac.set_payload(msg);
mac.key(key);
mac.gen_tag(null);
mac.encode(true);
```
### Decode cose-mac0
```js
// Prepare cose-key
let key = new CoseKey();
key.set_kty(Kty.symmetric);
key.set_alg(Alg.aes_mac_256_128);
key.set_k(Buffer.from('849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188', 'hex'));
key.set_key_ops([KeyOp.mac_verify]);

// Prepare CoseMAC with the cose-mac0 bytes
let verify = new CoseMAC();
verify.set_bytes(Buffer.from("d18444a101181aa054546869732069732074686520636f6e74656e742e50403152cc208c1d501e1dc2a789ae49e4", "hex"));

// Init decoding and add key
verify.init_decoder(null);
verify.key(key);

// Verify cose-mac0 tag
verify.decode(null);
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

// Prepare cose-mac header
let header = new CoseHeader();
header.set_alg(Alg.aes_mac_256_128, true, false);
header.set_iv(Buffer.from('89f52f65a1c580933b5261a7', 'hex'), true, false);

// Prepare CoseMAC
let mac = new CoseMAC();
mac.set_header(header);
mac.set_payload(msg);

// Add recipient 1
let recipient1 = new CoseAgent();
header = new CoseHeader();
header.set_alg(Alg.a128kw, true, false);
header.set_kid(Buffer.from("3131", "hex"), false, false);
recipient1.set_header(header);
recipient1.key(key1);
mac.add_recipient(recipient1);

// Add recipient 2
let recipient2 = new CoseAgent();
header = new CoseHeader();
header.set_alg(Alg.ecdh_es_a128kw, true, false);
header.set_kid(Buffer.from("3232", "hex"), false, false);
recipient2.set_header(header);
recipient2.key(key2);
recipient2.ephemeral_key(eph_key2, true, false);
mac.add_recipient(recipient2);

// Generate tag and encode final message
mac.gen_tag(null);
mac.encode(true);
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
key2.set_alg(Alg.es256);
key2.set_crv(Crv.p_256);
key2.set_d(Buffer.from('02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3', 'hex'));
key2.set_key_ops([KeyOp.derive]);

// Prepare CoseMAC with the cose-mac bytes
let verify = new CoseMAC();
verify.set_bytes(Buffer.from("d8618552a201181a054c89f52f65a1c580933b5261a7a054546869732069732074686520636f6e74656e742e50294e0160dbb25ee48703e918c6051f88828343a10122a10442313158283f27043f090c4d2af4398c10ca06e8d422da75882a58395ffceba7c6357cf031bc5216ba0b566673835832a201381c20a5010203262001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff048107a104423232582864b13f3ac9d8e8b34a40379320d7f757ab992a0ec0cd0436b67af178eb1bf50690fe9d13a854c2c3", "hex"));

// Init decoding
verify.init_decoder(null);

// Get recipient 1 and verify tag
let recipient1_i = verify.get_recipient(Buffer.from("3131", "hex"))[0];
verify.add_recipient_key(recipient1_i, key1);
verify.decode(null, recipient1_i);

// Get recipient 2 and verify tag
let recipient2_i = verify.get_recipient(Buffer.from("3232", "hex"))[0];
verify.add_recipient_key(recipient2_i, key2);
verify.decode(null, recipient2_i);
```
