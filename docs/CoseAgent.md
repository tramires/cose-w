# CoseAgent documentation

Module to build COSE message agents (signers, recipients and counter signers).

## Properties

| Name | Type | Getter | Setter | Description |
| ---- | ---- | ------ | ------ | ----------- |
| `header` | [CoseHeader](CoseHeader.md) | Yes | Yes | COSE header object. | 
| `payload` | `Uint8Array` | Yes | No | Payload of the agent object (ciphertext or signature). |

When decoding a COSE message, after the function `init_decoding`, all the COSE message parameters will be accessible by the previously listed getters.

## Methods 

| Name | Parameters | Returns | Description |
| ---- | ---------- | ------- | ----------- |
| `key(key: CoseKey)` | `key`: COSE key. | --- |  Sets the COSE key to be used. | 
| `ephemeral_key(key: CoseKey, prot: bool, crit: bool)` | `key`: COSE ephemeral key. <br/> `prot`: If its to be included in protected header. <br/> `crit`: If its to be included in `crit` COSE array. | --- | Sets the COSE ephemeral key for Direct Key Agreement. | 
| `static_key(key: CoseKey, prot: bool, crit: bool)` | `key`: COSE static key. <br/> `prot`: If to be included in protected header. <br/> `crit`: If its to be included in `crit` COSE array. | --- | Sets the COSE static key for Direct Key Agreement. | 
| `static_kid(kid: Uint8Array, key: CoseKey, prot: bool, crit: bool)` | `kid`: Static Key ID. <br/> `key`: COSE static key. <br/> `prot`: If to be included in protected header. <br/> `crit`: If its to be included in `crit` COSE array. | --- | Sets the COSE static key for Direct Key Agreement, including only the Key ID on the final COSE message. | 
| `add_signature(signature: Uint8Array)` | `signature`: COSE signature. | --- | Sets the Counter Signature (Method to be used when the counter signature is produced externally. | 


# Examples

Examples with recipients/signers can be found in each COSE message type Module.

## Counter signers

Counter signature in cose-sign1 message.

### Encode
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

let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare signer cose-key
let key1 = new CoseKey();
key1.kty = Kty.ec2;
key1.alg = Alg.es256;
key1.crv = Crv.p_256;
key1.d = Buffer.from('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex');
key1.key_ops = [KeyOp.sign];

// Prepare counter signer cose-key
let key2 = new CoseKey();
key2.kty = Kty.ec2;
key2.alg = Alg.es256;
key2.crv = Crv.p_256;
key2.d = Buffer.from('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex');
key2.key_ops = [KeyOp.sign];


// Prepare CoseSign
let sign = CoseMessage.new_sign();
sign.payload = msg;
let header = new CoseHeader();
header.set_alg(Alg.es256, true, false);
header.set_kid([1], true, false);
sign.header = header;
sign.key(key1);

// Generate signature
sign.secure_content(null);

// Prepare counter signer
let counter1 = CoseAgent.new_counter_sig();
header = new CoseHeader();
header.set_kid([0], true, false);
header.set_alg(Alg.es256, true, false);
counter1.header = header;
counter1.key(key1);

// Add counter signature to cose-sign1
sign.counter_sig(null, counter1);
sign.add_counter_sig(counter1);

// Encode the cose-sign1 message
let bytes = sign.encode(true);
```

### Decode
```js
var {
  CoseKey,
  CoseMessage,
  Alg,
  Kty,
  Crv,
  KeyOp
} = require('cose-w');

// Prepare signer cose-key
let key1 = new CoseKey();
key1.kty = Kty.ec2;
key1.alg = Alg.es256;
key1.crv = Crv.p_256;
key1.x = Buffer.from('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', 'hex');
key1.y = Buffer.from('20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e', 'hex');
key1.key_ops = [KeyOp.verify];

// Prepare counter signer cose-key
let key2 = new CoseKey();
key2.kty = Kty.ec2;
key2.alg = Alg.es256;
key2.crv = Crv.p_256;
key2.x = Buffer.from('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', 'hex');
key2.y = Buffer.from('20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e', 'hex');
key2.key_ops = [KeyOp.verify];

// Prepare CoseSign with the cose-sign1 bytes
let verify = CoseMessage.new_sign();
verify.bytes = Buffer.from("d28446a20126044101a1078346a20441000126a05840b94eb54af9aba9250c3aabf65c7da5583d0c1b4e813f9dead8b5ac0fbc3afa2ae57ae88905c80f100771394501bc447d6064afcbdf88bb0620863f1e0827406554546869732069732074686520636f6e74656e742e5840cf6f9dd76e5c7252e72bf6bf685fced5d82309c4ae0df229a501529636106ae99ddb5efc8b73c208ddbc815f91d71dc9b7db8ce6390f76ad01ba256fc0eae575", "hex");

// Init decoding
verify.init_decoder(null);

// Add key and verify signature
verify.key(key1);
let payload = verify.decode(null, null);

// Get counter signer and verify counter signature
let i = verify.counter([0]);
verify.set_counter_key(i, null, key1);
verify.counters_verify(null, i, null);
```
