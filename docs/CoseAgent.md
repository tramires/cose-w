# CoseAgent documentation

Module to build COSE message agents (signers, recipients and counter signers).

## Getters

- `header`: CoseHeader of the CoseAgent.
- `payload`: Payload of the CoseAgent (ciphertext or signature).

When decoding a COSE message, after the function `init_decoding`, all the COSE message parameters will be accessible by the previously listed getters.

## Methods 

- Counter signatures:
- `new_counter_sig()`: Initiates a CoseAgent with the Counter Signer context.
- `set_header(header: CoseHeader)`: Sets the COSE header.
- `key(key: keys::CoseKey)`: Sets the key to be used.
- `ephemeral_key(key: keys::CoseKey, prot: bool, crit: bool)`: Adds the ephemeral ECDH COSE key to the CoseAgent.
- `static_key(key: keys::CoseKey, prot: bool, crit: bool)`: Adds the static ECDH COSE key to the CoseAgent.
- `set_static_kid(kid: Vec<u8>, key: keys::CoseKey, prot: bool, crit: bool)`: Adds the static ECDH COSE key and static key ID to the CoseAgent.
- `add_signature(signature: Vec<u8>)`: Sets counter signature (Method used when the counter signature is produced out of the COSE message encoding).

# Examples

Examples with recipients/signers can be found in each COSE message type Module.

## Counter signers

Counter signature in cose-sign1 message.

### Encode
```js
let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare signer cose-key
let key1 = new CoseKey();
key1.set_kty(Kty.ec2);
key1.set_alg(Alg.es256);
key1.set_crv(Crv.p_256);
key1.set_d(Buffer.from('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex'));
key1.set_key_ops([KeyOp.sign]);

// Prepare counter signer cose-key
let key2 = new CoseKey();
key2.set_kty(Kty.ec2);
key2.set_alg(Alg.es256);
key2.set_crv(Crv.p_256);
key2.set_d(Buffer.from('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex'));
key2.set_key_ops([KeyOp.sign]);


// Prepare CoseSign
let sign = new CoseSign();
sign.set_payload(msg);
let header = new CoseHeader();
header.set_alg(Alg.es256, true, false);
header.set_kid([1], true, false);
sign.set_header(header);
sign.key(key1);

// Generate signature
sign.gen_signature(null);

// Prepare counter signer
let counter1 = CoseAgent.new_counter_sig();
header = new CoseHeader();
header.set_kid([0], true, false);
header.set_alg(Alg.es256, true, false);
counter1.set_header(header);
counter1.key(key1);

// Add counter signature to cose-sign1
sign.counter_sig(null, counter1);
sign.add_counter_sig(counter1);

// Encode the cose-sign1 message
sign.encode(true);
```

### Decode
```js
// Prepare signer cose-key
let key1 = new CoseKey();
key1.set_kty(Kty.ec2);
key1.set_alg(Alg.es256);
key1.set_crv(Crv.p_256);
key1.set_x(Buffer.from('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', 'hex'));
key1.set_y(Buffer.from('20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e', 'hex'));
key1.set_key_ops([KeyOp.verify]);

// Prepare counter signer cose-key
let key2 = new CoseKey();
key2.set_kty(Kty.ec2);
key2.set_alg(Alg.es256);
key2.set_crv(Crv.p_256);
key2.set_x(Buffer.from('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', 'hex'));
key2.set_y(Buffer.from('20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e', 'hex'));
key2.set_key_ops([KeyOp.verify]);

// Prepare CoseSign with the cose-sign1 bytes
let verify = new CoseSign();
verify.set_bytes(Buffer.from("d28446a20126044101a1078346a20441000126a0584019b7fc0f2b13cd8d1891beb3d5fcadb79dfd14384f48059454cbab16e01503a261e8f5dc47aa998782b7baa74b260ec5dd3694e44f88c99c5db7f61ff8aca23954546869732069732074686520636f6e74656e742e5840cf6f9dd76e5c7252e72bf6bf685fced5d82309c4ae0df229a501529636106ae99ddb5efc8b73c208ddbc815f91d71dc9b7db8ce6390f76ad01ba256fc0eae575", "hex"));

// Init decoding
verify.init_decoder(null);

// Add key and verify signature
verify.key(key1);
verify.decode(null, null);

// Get counter signer and verify counter signature
let i = verify.counter([0]);
verify.add_counter_key(i, key1);
verify.counters_verify(null, i);
```
