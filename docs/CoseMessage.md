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
var {
  CoseKey,
  CoseMessage,
  CoseHeader,
  CoseAgent,
  Alg,
  Kty,
  Crv,
  KeyOp
} = require('cose-w');

// Message to sign, "This is the content."
let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare signer 1 cose-key
let key1 = new CoseKey();
key1.kty = Kty.ec2;
key1.alg = Alg.es256;
key1.crv = Crv.p_256;
key1.d = Buffer.from('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex');
key1.key_ops = [KeyOp.sign];

// Prepare signer2 cose-key
let key2 = new CoseKey();
key2.kty = Kty.ec2;
key2.alg = Alg.es256;
key2.crv = Crv.p_256;
key2.d = Buffer.from('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex');
key2.key_ops = [KeyOp.sign];

// Prepare CoseSign
let sign = CoseMessage.new_sign();
sign.payload = msg;

// Add signer 1
let signer1 = new CoseAgent();
let header = new CoseHeader();
header.set_alg(Alg.es256, true, false);
header.set_kid([1], true, false);
signer1.header = header;
signer1.key(key1);
sign.add_agent(signer1);

// Add signer 2
let signer2 = new CoseAgent();
header = new CoseHeader();
header.set_alg(Alg.es256, true, false);
header.set_kid([2], true, false);
signer2.header = header;
signer2.key(key2);
sign.add_agent(signer2);

// Generate signature and encode cose-sign message
sign.secure_content(null);
let bytes = sign.encode(true);
```

### Decode cose-sign 
```js
var {
  CoseKey,
  CoseMessage,
  Alg,
  Kty,
  Crv,
  KeyOp
} = require('cose-w');

// Prepare signer 1 cose-key
let key1 = new CoseKey();
key1.kty = Kty.ec2;
key1.alg = Alg.es256;
key1.crv = Crv.p_256;
key1.x = Buffer.from('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', 'hex');
key1.y = Buffer.from('20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e', 'hex');
key1.key_ops = [KeyOp.verify];

// Prepare signer2 cose-key
let key2 = new CoseKey();
key2.kty = Kty.ec2;
key2.alg = Alg.es256;
key2.crv = Crv.p_256;
key2.x = Buffer.from('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', 'hex');
key2.y = Buffer.from('20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e', 'hex');
key2.key_ops = [KeyOp.verify];

// Prepare CoseSign with the cose-sign bytes
let verify = CoseMessage.new_sign();
verify.bytes = Buffer.from("d8628440a054546869732069732074686520636f6e74656e742e828346a20126044101a058408d53d4fd916a66c7e93979c0d68938045b35902ab0ae880c503be2830d4c99af187519115debf9e4f54475a2c71c6e6042f4b7d2bcfef9860487b7a4ae36d2cf8346a20126044102a05840ea1664340920c3eff80c6d97c7896b2e42992afa461b734f04bbd33d4237e96f320f1dfdef3cb8f8979456e4dc931403e74d88fc4af77fc9ec5264a27f30a022", "hex");

// Init decoding
verify.init_decoder(null);

// Get signer 1 and verify
let signer1_i = verify.get_agent([1])[0];
verify.set_agent_key(signer1_i, key1);
verify.decode(null, signer1_i);

// Get signer 2 and verify
let signer2_i = verify.get_agent([2])[0];
verify.set_agent_key(signer2_i, key2);
let payload = verify.decode(null, signer2_i);
```

## cose-encrypt

Encode/decode cose-encrypt.

### Encode cose-encrypt
```js
var {
  CoseKey,
  CoseMessage,
  CoseHeader,
  CoseAgent,
  Alg,
  Kty,
  Crv,
  KeyOp
} = require('cose-w');

// Message to encrypt, "This is the content."
let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare recipient 1 cose-key
let key1 = new CoseKey();
key1.kty = Kty.symmetric;
key1.alg = Alg.a128kw;
key1.k = Buffer.from('849b57219dae48de646d07dbb533566e', 'hex');
key1.key_ops = [KeyOp.wrap];

// Prepare recipient 2 cose-key
let key2 = new CoseKey();
key2.kty = Kty.ec2;
key2.crv = Crv.p_256;
key2.x = Buffer.from('98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280', 'hex');
key2.y = Buffer.from('F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB', 'hex');

// Prepare recipient 2 ephemeral ECDH cose-key
let eph_key2 = new CoseKey();
eph_key2.kty = Kty.ec2;
eph_key2.crv = Crv.p_256;
eph_key2.x = Buffer.from('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', 'hex');
eph_key2.d = Buffer.from('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex');
eph_key2.key_ops = [KeyOp.derive];

// Prepare cose-encrypt header
let header = new CoseHeader();
header.set_alg(Alg.a256gcm, true, false);
header.set_iv(Buffer.from('89f52f65a1c580933b5261a7', 'hex'), true, false);

// Prepare CoseEncrypt
let enc = CoseMessage.new_encrypt();
enc.header = header;
enc.payload = msg;

// Add recipient 1
let recipient1 = new CoseAgent();
header = new CoseHeader();
header.set_alg(Alg.a128kw, true, false);
header.set_kid([0], false, false);
recipient1.header = header;
recipient1.key(key1);
enc.add_agent(recipient1);

// Add recipient 2
let recipient2 = new CoseAgent();
header = new CoseHeader();
header.set_alg(Alg.ecdh_es_a128kw, true, false);
header.set_kid([1], false, false);
recipient2.header = header;
recipient2.key(key2);
recipient2.ephemeral_key(eph_key2, true, false);
enc.add_agent(recipient2);

// Gen ciphertext and encode
enc.secure_content(null);
let bytes = enc.encode(true);
```
### Decode cose-encrypt
```js
var {
  CoseKey,
  CoseMessage,
  Alg,
  Kty,
  Crv,
  KeyOp
} = require('cose-w');
var assert = require('assert');

// Expected messsage to decrypt
let expected_msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare recipient 1 cose-key
let key1 = new CoseKey();
key1.kty = Kty.symmetric;
key1.alg = Alg.a128kw;
key1.k = Buffer.from('849b57219dae48de646d07dbb533566e', 'hex');
key1.key_ops = [KeyOp.unwrap];

// Prepare recipient 2 cose-key
let key2 = new CoseKey();
key2.kty = Kty.ec2;
key2.crv = Crv.p_256;
key2.d = Buffer.from('02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3', 'hex');
key2.key_ops = [KeyOp.derive];

// Prepare CoseEncrypt with the cose-encrypt bytes
let dec = CoseMessage.new_encrypt();
dec.bytes = Buffer.from("d8608451a20103054c89f52f65a1c580933b5261a7a05824b405d0fdca0bc1cad073275e402933c19e198d4d8b69c6cbceef55c231becbe8a7d5604e828343a10122a10441005828bc703be59088671a557a928670186af85da2157a7b1d23cf0c0c53ee89c7819028eb343c29545a8f835832a201381c20a5010203262001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff048107a1044101582813e5bf1bc51a20fed5b199dd0d8cbeaaf899ab272a52794b0e46a94f66a413cb21c7c15d632c7169", "hex");

// Init decoding
dec.init_decoder(null);

// Get recipient 1 and decrypt
let recipient1_i = dec.get_agent([0])[0];
let info = dec.agent_header(recipient1_i);
dec.set_agent_key(recipient1_i, key1);
let msg = dec.decode(null, recipient1_i);
assert.deepEqual(Buffer.from(msg).toString(), expected_msg.toString());


// Get recipient 2 and decrypt
let recipient2_i = dec.get_agent([1])[0];
dec.set_agent_key(recipient2_i, key2);
msg = dec.decode(null, recipient2_i);
assert.deepEqual(Buffer.from(msg).toString(), expected_msg.toString());
```

## cose-mac

Encode/decode cose-mac.

### Encode cose-mac
```js
var {
  CoseKey,
  CoseMessage,
  CoseHeader,
  CoseAgent,
  Alg,
  Kty,
  Crv,
  KeyOp
} = require('cose-w');

// Message to MAC, "This is the content."
let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare recipient 1 cose-key
let key1 = new CoseKey();
key1.kty = Kty.symmetric;
key1.alg = Alg.a128kw;
key1.k = Buffer.from('849b57219dae48de646d07dbb533566e', 'hex');
key1.key_ops = [KeyOp.wrap, KeyOp.unwrap];

// Prepare recipient 2 cose-key
let key2 = new CoseKey();
key2.kty = Kty.ec2;
key2.crv = Crv.p_256;
key2.x = Buffer.from('98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280', 'hex');
key2.y = Buffer.from('F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB', 'hex');

// Prepare recipient 2 ephemeral ECDH cose-key
let eph_key2 = new CoseKey();
eph_key2.kty = Kty.ec2;
eph_key2.crv = Crv.p_256;
eph_key2.x = Buffer.from('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', 'hex');
eph_key2.d = Buffer.from('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex');
eph_key2.key_ops = [KeyOp.derive];

// Prepare cose-mac header
let header = new CoseHeader();
header.set_alg(Alg.aes_mac_256_128, true, false);
header.set_iv(Buffer.from('89f52f65a1c580933b5261a7', 'hex'), true, false);

// Prepare CoseMAC
let mac = CoseMessage.new_mac();
mac.header = header;
mac.payload = msg;

// Add recipient 1
let recipient1 = new CoseAgent();
header = new CoseHeader();
header.set_alg(Alg.a128kw, true, false);
header.set_kid(Buffer.from("3131", "hex"), false, false);
recipient1.header = header;
recipient1.key(key1);
mac.add_agent(recipient1);

// Add recipient 2
let recipient2 = new CoseAgent();
header = new CoseHeader();
header.set_alg(Alg.ecdh_es_a128kw, true, false);
header.set_kid(Buffer.from("3232", "hex"), false, false);
recipient2.header = header;
recipient2.key(key2);
recipient2.ephemeral_key(eph_key2, true, false);
mac.add_agent(recipient2);

// Generate tag and encode final message
mac.secure_content(null);
let bytes = mac.encode(true);
```
### Decode cose-mac
```js
var {
  CoseKey,
  CoseMessage,
  Alg,
  Kty,
  Crv,
  KeyOp
} = require('cose-w');

// Prepare recipient 1 cose-key
let key1 = new CoseKey();
key1.kty = Kty.symmetric;
key1.alg = Alg.a128kw;
key1.k = Buffer.from('849b57219dae48de646d07dbb533566e', 'hex');
key1.key_ops = [KeyOp.unwrap];

// Prepare recipient 2 cose-key
let key2 = new CoseKey();
key2.kty = Kty.ec2;
key2.crv = Crv.p_256;
key2.d = Buffer.from('02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3', 'hex');
key2.key_ops = [KeyOp.derive];

// Prepare CoseMAC with the cose-mac bytes
let verify = CoseMessage.new_mac();
verify.bytes = Buffer.from("d8618552a201181a054c89f52f65a1c580933b5261a7a054546869732069732074686520636f6e74656e742e50294e0160dbb25ee48703e918c6051f88828343a10122a10442313158283f27043f090c4d2af4398c10ca06e8d422da75882a58395ffceba7c6357cf031bc5216ba0b566673835832a201381c20a5010203262001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff048107a104423232582864b13f3ac9d8e8b34a40379320d7f757ab992a0ec0cd0436b67af178eb1bf50690fe9d13a854c2c3", "hex");

// Init decoding
verify.init_decoder(null);

// Get recipient 1 and verify tag
let recipient1_i = verify.get_agent(Buffer.from("3131", "hex"))[0];
verify.set_agent_key(recipient1_i, key1);
verify.decode(null, recipient1_i);

// Get recipient 2 and verify tag
let recipient2_i = verify.get_agent(Buffer.from("3232", "hex"))[0];
verify.set_agent_key(recipient2_i, key2);
let payload = verify.decode(null, recipient2_i);
```
