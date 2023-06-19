# CoseSign documentation

Module to encode/decode cose-sign1 and cose-sign messages.

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
- `key(key: keys::CoseKey)`: Sets key to be used in case of cose-sign1 message.
- `set_key(key: keys::CoseKey)`: Sets key to be used in case of cose-sign1 message.
- `gen_signature(external_aad: Option<Vec<u8>>)`: Generate signature with optional external AAD.
- `encode(payload: bool)`: Encode the final message, payload parameter defines if the payload is to be included in the COSE encoded message.
- `init_decoder(payload: Option<Vec<u8>>)`: Initial decoding of the COSE message to accesss the message atributes to further validate/decode the message, the parameter payload needs to be provided if its not included in the encoded COSE message.
- `decode(external_aad: Option<Vec<u8>>, signer: Option<usize>)`: Final decode of the COSE message, with the option to include external AAD. If cose-sign1 type message, the signer parameter can be null, else if cose-sign type, a signer index must be provided and the respective signer key must be set.

### Signers:

Methods for when using cose-sign message type:

- `signer_header(i: usize)`: Get the signer header.
- `add_signer(signer: &mut CoseAgent)`: Add signer to the message.
- `get_signer(kid: Vec<u8>)`: Get signers with the provided key ID.
- `pub fn add_signer_key(index: usize, cose_key: CoseKey)`: Adds a COSE key to a signer.

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

## cose-sign1

Encode/decode cose-sign1.

### Encode cose-sign1 
```js
// Message to sign, "This is the content."
let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare cose-key
let key = new CoseKey();
key.set_kty(Kty.ec2);
key.set_alg(Alg.es256);
key.set_crv(Crv.p_256);
key.set_d(Buffer.from('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex'));
key.set_key_ops([KeyOp.sign]);

// Prepare cose-sign1 header
let header = new CoseHeader();
header.set_alg(Alg.es256, true, false);
header.set_kid([49, 49], true, false);

// Generate CoseSign and encode the cose-sign1 final message
let signer = new CoseSign();
signer.set_header(header);
signer.set_payload(msg);
signer.key(key);
signer.gen_signature(null);
signer.encode(true);
```

### Decode cose-sign1 
```js
// Prepare cose-key
let key = new CoseKey();
key.set_kty(Kty.ec2);
key.set_alg(Alg.es256);
key.set_crv(Crv.p_256);
key.set_x(Buffer.from('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', 'hex'));
key.set_y(Buffer.from('20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e', 'hex'));
key.set_key_ops([KeyOp.verify]);

// Prepare CoseSign with the cose-sign1 bytes
let verify = new CoseSign();
verify.set_bytes(Buffer.from("d28447a2012604423131a054546869732069732074686520636f6e74656e742e58405e84ce5812b0966e6919ff1ac15c030666bae902c0705d1e0a5fbac828437c63b0bb87a95a456835f4d115850adefcf0fd0a5c26027140c10d3e20a890c5eaa7", "hex"));

// Init decoding and add key
verify.init_decoder(null);
verify.key(key);

// Verify cose-sign1
verify.decode(null, null);
```
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
let sign = new CoseSign();
sign.set_payload(msg);

// Add signer 1
let signer1 = new CoseAgent();
let header = new CoseHeader();
header.set_alg(Alg.es256, true, false);
header.set_kid([1], true, false);
signer1.set_header(header);
signer1.key(key1);
sign.add_signer(signer1);

// Add signer 2
let signer2 = new CoseAgent();
header = new CoseHeader();
header.set_alg(Alg.es256, true, false);
header.set_kid([2], true, false);
signer2.set_header(header);
signer2.key(key2);
sign.add_signer(signer2);

// Generate signature and encode cose-sign message
sign.gen_signature(null);
sign.encode(true);
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
let verify = new CoseSign();
verify.set_bytes(Buffer.from("d8628440a054546869732069732074686520636f6e74656e742e828346a20126044101a058408d53d4fd916a66c7e93979c0d68938045b35902ab0ae880c503be2830d4c99af187519115debf9e4f54475a2c71c6e6042f4b7d2bcfef9860487b7a4ae36d2cf8346a20126044102a05840ea1664340920c3eff80c6d97c7896b2e42992afa461b734f04bbd33d4237e96f320f1dfdef3cb8f8979456e4dc931403e74d88fc4af77fc9ec5264a27f30a022", "hex"));

// Init decoding
verify.init_decoder(null);

// Get signer 1 and verify
let signer1_i = verify.get_signer([1])[0];
verify.add_signer_key(signer1_i, key1);
verify.decode(null, signer1_i);

// Get signer 2 and verify
let signer2_i = verify.get_signer([2])[0];
verify.add_signer_key(signer2_i, key2);
verify.decode(null, signer2_i);
```
