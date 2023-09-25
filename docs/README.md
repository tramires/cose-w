# Documentation

- [CoseMessage](CoseMessage.md): Module for all types of COSE messages (cose-sign1, cose-mac0, cose-encrypt0, cose-sign, cose-mac and cose-encrypt).
- [CoseAgent](CoseAgent.md): COSE signers, recipients and counter-signers module.
- [CoseHeader](CoseHeader.md): COSE headers (protected and unprotected) module.
- [CoseKey](CoseKey.md): COSE keys module. 
- [CoseKeySet](CoseKeySet.md): COSE KeySet module. 
- [Constants](Constants.md): COSE constants.

# Examples

The following examples, demonstrate how to encode and decode the basic COSE messages (cose-sign1, cose-encrypt0, cose-mac0), examples of other use cases and cose message types
can be found in the respective documentation.

## cose-sign1

Encode/decode cose-sign1.

### Encode cose-sign1 
```js
var {
  CoseKey,
  CoseHeader,
  CoseMessage,
  Alg,
  Kty,
  Crv,
  KeyOp
} = require('cose-w');

// Message to sign, "This is the content."
let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare cose-key
let key = new CoseKey();
key.kty = Kty.ec2;
key.alg = Alg.es256;
key.crv = Crv.p_256;
key.d = Buffer.from('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex');
key.key_ops = [KeyOp.sign];

// Prepare cose-sign1 header
let header = new CoseHeader();
header.set_alg(Alg.es256, true, false);
header.set_kid([49, 49], true, false);

// Generate CoseSign and encode the cose-sign1 final message
let signer = CoseMessage.new_sign();
signer.header = header;
signer.payload = msg;
signer.key(key);
signer.secure_content(null);
let bytes = signer.encode(true);
```

### Decode cose-sign1 
```js
var {
  CoseKey,
  CoseMessage,
  Alg,
  Kty,
  Crv,
  KeyOp
} = require('cose-w');

// Prepare cose-key
let key = new CoseKey();
key.kty = Kty.ec2;
key.alg = Alg.es256;
key.crv = Crv.p_256;
key.x = Buffer.from('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', 'hex');
key.y = Buffer.from('20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e', 'hex');
key.key_ops = [KeyOp.verify];

// Prepare CoseSign with the cose-sign1 bytes
let verify = CoseMessage.new_sign();
verify.bytes = Buffer.from("d28447a2012604423131a054546869732069732074686520636f6e74656e742e58405e84ce5812b0966e6919ff1ac15c030666bae902c0705d1e0a5fbac828437c63b0bb87a95a456835f4d115850adefcf0fd0a5c26027140c10d3e20a890c5eaa7", "hex");

// Init decoding and add key
verify.init_decoder(null);
verify.key(key);

// Verify cose-sign1
let payload = verify.decode(null, null);
```

## cose-encrypt0

Encode/decode cose-encrypt0.

### Encode cose-encrypt0
```js
var {
  CoseKey,
  CoseHeader,
  CoseMessage,
  Alg,
  Kty,
  KeyOp
} = require('cose-w');

// Message to encrypt, "This is the content."
let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare cose-key
let key = new CoseKey();
key.kty = Kty.symmetric;
key.alg = Alg.chacha20;
key.k = Buffer.from('849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188', 'hex');
key.key_ops = [KeyOp.encrypt];

// Prepare cose-encrypt0 header
let header = new CoseHeader();
header.set_alg(Alg.chacha20, true, false);
header.set_iv(Buffer.from('89f52f65a1c580933b5261a7', 'hex'), true, false);

// Generate CoseEncrypt and encode the cose-encrypt0 final message
let enc = CoseMessage.new_encrypt();
enc.header = header;
enc.payload = msg;
enc.key(key);
enc.secure_content(null);
let bytes = enc.encode(true);
```

### Decode cose-encrypt0
```js
var {
  CoseKey,
  CoseMessage,
  Alg,
  Kty,
  KeyOp
} = require('cose-w');
var assert = require('assert');

// "This is the content."
let expected_msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare cose-key
let key = new CoseKey();
key.kty = Kty.symmetric;
key.alg = Alg.chacha20;
key.k = Buffer.from('849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188', 'hex');
key.key_ops = [KeyOp.decrypt];

// Prepare CoseEncrypt with the cose-encrypt0 bytes
let dec = CoseMessage.new_encrypt();
dec.bytes = Buffer.from("d08352a2011818054c89f52f65a1c580933b5261a7a0582481c32c048134989007b3b5b932811ea410eeab15bd0de5d5ac5be03c84dce8c88871d6e9", "hex");

// Init decoding and add key
dec.init_decoder(null);
dec.key(key);

// Decrypt and verify cose-encrypt0 message
let msg = dec.decode(null);
assert.deepEqual(new Buffer.from(msg).toString(), expected_msg.toString());
```

## cose-mac0

Encode/decode cose-mac0.

### Encode cose-mac0
```js
var {
  CoseKey,
  CoseHeader,
  CoseMessage,
  Alg,
  Kty,
  KeyOp
} = require('cose-w');

// Message to MAC, "This is the content."
let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare cose-key
let key = new CoseKey();
key.kty = Kty.symmetric;
key.alg = Alg.aes_mac_256_128;
key.k = Buffer.from('849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188', 'hex');
key.key_ops = [KeyOp.mac];

// Prepare cose-mac0 header
let header = new CoseHeader();
header.set_alg(Alg.aes_mac_256_128, true, false);

// Generate CoseMAC and encode the cose-mac0 final message
let mac = CoseMessage.new_mac();
mac.header = header;
mac.payload = msg;
mac.key(key);
mac.secure_content(null);
let bytes = mac.encode(true);
```
### Decode cose-mac0
```js
var {
  CoseKey,
  CoseMessage,
  Alg,
  Kty,
  KeyOp
} = require('cose-w');

// Prepare cose-key
let key = new CoseKey();
key.kty = Kty.symmetric;
key.alg = Alg.aes_mac_256_128;
key.k = Buffer.from('849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188', 'hex');
key.key_ops = [KeyOp.mac_verify];

// Prepare CoseMAC with the cose-mac0 bytes
let verify = CoseMessage.new_mac();
verify.bytes = Buffer.from("d18444a101181aa054546869732069732074686520636f6e74656e742e50403152cc208c1d501e1dc2a789ae49e4", "hex");

// Init decoding and add key
verify.init_decoder(null);
verify.key(key);

// Verify cose-mac0 tag
let payload = verify.decode(null);
```
