# CoseMessage documentation

Module to encode/decode COSE messages.


## Constructors:

| Name |  Description |
| ---- | ----------- |
| `new_sign` | Initiates a COSE sign message type (cose-sign1 and cose-sign). | 
| `new_encrypt` | Initiates a COSE encrypt message type (cose-encrypt0 and cose-encrypt). | 
| `new_mac` | Initiates a COSE mac message type (cose-mac0 and cose-mac). | 

## Properties

| Name | Type | Getter | Setter | Description |
| ---- | ---- | ------ | ------ | ----------- |
| `header` | [CoseHeader](CoseHeader.md) | Yes | Yes | COSE header object of the message. | 
| `bytes` | `Uint8Array` | Yes | Yes | Final encoded message in bytes. | 
| `payload` | `Uint8Array` | Yes | Yes | Payload of the message in bytes. | 


When decoding a COSE message, after the function `init_decoding`, all the COSE message parameters will be accessible by the previously listed getters.

## Methods 

| Name | Parameters | Returns | Description |
| ---- | ---------- | ------- | ----------- |
| `key(key: CoseKey)` | `key`: COSE key. | --- | Sets the COSE key to be used (Method to be only used when COSE message type is cose-sign1, cose-mac0 or cose-encrypt0). | 
| `secure_content(external_aad?: Uint8Array)` | `external_aad`: Optional external AAD. | --- | Generate the MAC, ciphertext or signature depending on the type of COSE message. | 
| `encode(payload: bool)` | `payload`: Boolean to determine if the payload is to be included in the COSE message or not. | Uint8Array | Encodes the final COSE message returning it as bytes. | 
| `init_decoder(payload?: Uint8Array)` | `payload`: Payload of the COSE message in case the payload is not included in the COSE message itself. | --- | Initial decoding of the COSE message in order to access the message attributes to further validate/decode the COSE message. | 
| `decode(external_aad?: Uint8Array, agent?: number)` | `external_aad`: Optional external AAD. `agent`: Position of the agent in the agents array that is to be decoded, if the COSE message type is cose-sign1, cose-mac0 or cose-encrypt0 the `agent` parameter must be `null`. | `Uint8Array`| Final decoding of the COSE message/recipient/signer returning the COSE message payload. | 


### Recipients/Signers use:

Methods for COSE messages with signers/recipients bucket.

| Name | Parameters | Returns | Description |
| ---- | ---------- | ------- | ----------- |
| `agent_header(i: number)` | `i`: Position of the agent in agents array. | [CoseHeader](CoseHeader.md) | Returns the agent header. | 
| `add_agent(agent: CoseAgent)` | `agent`: COSE agent to add to the COSE message. | --- | Adds a signer/recipient to the COSE message. | 
| `get_agent(kid: Uint8Array)` | `kid`: COSE Key ID. | --- | Returns the positions of signers/recipients with the provided Key ID. | 
| `set_agent_key(agent: number, cose_key: CoseKey)` | `agent`: Position of the agent in the agents array.<br/> `cose_key`: COSE key. | --- | Sets the COSE key of the respective signer/recipient. | 
| `set_agent_pub_other(agent: number, other: Uint8Array)` | `agent`: Position of the agent in agents array. <br/> `other`: SuppPubInfo `other` value. | --- | Sets the respective signer/recipient other field of SuppPubInfo. | 
| `set_agent_priv_info(agent: number, info: Uint8Array)` | `agent`: Position of the agent in agents array. <br/> `info`: SuppPrivInfo. | --- | Sets the respective signer/recipient SuppPrivInfo value. | 
| `set_agent_party_identity(agent: number, id: Uint8Array, u: bool)` | `agent`: Position of the agent in agents array. <br/> `id`: Party Identity value. <br/> `u`: If its Party U or V | --- | Sets the respective signer/recipient Party U or V Identity. | 
| `set_agent_ecdh_key(agent: number, key: CoseKey)` | `agent`: Position of the agent in agents array. <br/> `key`: ECDH COSE Key. | --- | Sets the respective signer/recipient ECDH COSE Key. | 


### Counter Signers:

Methods for COSE messages with counter signatures:

| Name | Parameters | Returns | Description |
| ---- | ---------- | ------- | ----------- |
| `counters_len(agent?: number)` | `agent`: agent position in the agents array of the message. | `number` | Returns the number of counter signatures of the COSE message or respective agent if `agent` parameter is not `null`. | 
| `counter_header(counter: number)` | `counter`: counter signature position in the counter signatures array of the message. | [CoseHeader](CoseHeader.md) | Returns the header of the respective counter signature. | 
| `counter(kid: Uint8Array)` | `kid`: Key ID to search. | --- | Returns the positions of counter signatures with the provided Key ID. | 
| `set_counter_key(counter: number, key: CoseKey)` | `counter`: Position of the counter signature in the array. <br/> `key`: COSE key. | --- | Adds a COSE key to the respective counter signer. | 
| `counter_sig(external_aad?: Uint8Array, counter: CoseAgent)` | `external_aad`: Optional external AAD. <br/> `counter`: Counter signer object to add to the message. | --- | Generates Counter Signature and adds to the COSE message. | 
| `counters_verify(external_aad?: Uint8Array, counter: number)` | `external_aad`: Optional external AAD. <br/> `counter`: Position of the counter signer in the array. | --- | Verifies a Counter Signature in the COSE message. | 
| `get_to_sign(external_aad?: Uint8Array, counter: CoseAgent)` | `external_aad`: Optional external AAD. <br/> `counter`: Counter signer object. | --- | Get COSE content to sign externally. | 
| `get_to_verify(external_aad?: Uint8Array, counter: CoseAgent)` | `external_aad`: Optional external AAD. <br/> `counter`: Counter signer object. | --- | Get COSE content to verify externally. | 
| `add_counter_sig(counter: CoseAgent` | `counter`: Counter signer object. | --- | Add Counter Signer object to the COSE message. | 


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
