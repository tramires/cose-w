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
| `agents` | `Vec<`[CoseAgent](CoseAgent.md)`>` | Yes | No | Cose Agents (Recipient,  Signer and Counter Signer) of the message (This is returns just a copy of the agents data due to the WASM limitations). | 


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

- cose-sign (Multiple signers COSE Sign message): [Encode](#encode-cose-sign) and
  [Decode](#decode-cose-sign)
- cose-encrypt (Multiple recipients COSE Encrypt message w/ Direct Key): [Encode](#encode-cose-encrypt) and [Decode](#decode-cose-encrypt)
- cose-mac (Multiple recipients COSE MAC message w/ ECDH): [Encode](#encode-cose-mac) and [Decode](#decode-cose-mac)
- Counter Signature: [Encode](#encode-counter-signature) and [Decode](#decode-counter-signature) 
- Counter Signature (Externally signed/verified): [Encode](#encode-externally-signed) and [Decode](#decode-externally-verified) 

Examples of single recipient messages (cose-sign1, cose-mac0 and cose-encrypt0) can be seen
[here](README.md).

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

let msg = Buffer.from('This is the content.', 'utf8');

// Prepare CoseSign
let sign = CoseMessage.new_sign();
sign.payload = msg;

let key = new CoseKey();

// Add signer 1
let signer1 = new CoseAgent();

key.bytes = Buffer.from("A601020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF", "hex");
key.decode();

let header = new CoseHeader();
header.set_alg(Alg.es256, true, false);
header.set_kid(key.kid, true, false);
signer1.header = header;

signer1.key(key);

sign.add_agent(signer1);

// Add signer 2
let signer2 = new CoseAgent();

key.bytes = Buffer.from("A60102024231312001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3", "hex");
key.decode();

header = new CoseHeader();
header.set_alg(Alg.es256, true, false);
header.set_kid(key.kid, true, false);
signer2.header = header;

signer2.key(key);

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

let key1 = new CoseKey();
key1.bytes = Buffer.from("A601020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF", "hex");
key1.decode();

let key2 = new CoseKey();
key2.bytes = Buffer.from("A60102024231312001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3", "hex");
key2.decode();

// Prepare CoseSign with the cose-sign bytes
let verify = CoseMessage.new_sign();
verify.bytes = Buffer.from("d8628440a054546869732069732074686520636f6e74656e742e8283582aa201260458246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65a05840b0714b778d405c76414fdefbc6499459a76a9f3741326b5b961ac7b87bf1f705697e5789eddb3ed722ca76eb125654b2a8b9f2135d2869bf4b97ddd90f16c5ab8347a2012604423131a058401234cb1cf8ca3ef16e78233a9e46192a17f7c70dbac76c7721f5a4da759ae1c3ccda943ecc62d12668a261550cc4bf39046f484f99ab9526c7916c09d189c0c1", "hex");

// Init decoding
verify.init_decoder(null);


// Get signer 1 and verify
let signer1_index = verify.get_agent(key1.kid)[0];
verify.set_agent_key(signer1_index, key1);
let payload = verify.decode(null, signer1_index);

// Get signer 2 and verify
let signer2_index = verify.get_agent(key2.kid)[0];
verify.set_agent_key(signer2_index, key2);
payload = verify.decode(null, signer2_index);
```

## cose-encrypt

Encode/decode cose-encrypt with Direct Key.

### Encode cose-encrypt
```js
let msg = Buffer.from('This is the content.', 'utf8');

// Prepare cose-encrypt header
let header = new CoseHeader();
header.set_alg(Alg.a128gcm, true, false);
header.set_iv(Buffer.from('89f52f65a1c580933b5261a7', 'hex'), false, false);

// Prepare CoseEncrypt
let enc = CoseMessage.new_encrypt();
enc.header = header;
enc.payload = msg;

// Add recipient 
let recipient = new CoseAgent();

// Prepare recipient cose-key
let key = new CoseKey();
key.bytes = Buffer.from("A30104024B6F75722D736563726574322050849B5786457C1491BE3A76DCEA6C4271", "hex");
key.decode();

header = new CoseHeader();
header.set_alg(Alg.direct, false, false);
header.set_kid(key.kid, false, false);
recipient.header = header;

recipient.key(key);

enc.add_agent(recipient);

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
let expected_msg = Buffer.from('This is the content.', 'utf8');

// Prepare CoseEncrypt with the cose-encrypt bytes
let dec = CoseMessage.new_encrypt();
dec.bytes = Buffer.from("d8608443a10101a1054c89f52f65a1c580933b5261a75824b148914af99b365b06a29477e0fbd05a57acf3f987392a3d49818c394fa4771bdb2c2fc5818340a20125044b6f75722d7365637265743240", "hex");

// Init decoding
dec.init_decoder(null);

assert.strictEqual(dec.agents.length, 1);

let key = new CoseKey();
key.bytes = Buffer.from("A30104024B6F75722D736563726574322050849B5786457C1491BE3A76DCEA6C4271", "hex");
key.decode();

// Get recipient 1 and decrypt
let recipient_index = dec.get_agent(key.kid)[0];

dec.set_agent_key(recipient_index, key);

let msg = dec.decode(null, recipient_index);
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

let msg = Buffer.from('This is the content.', 'utf8');

// Prepare cose-mac header
let header = new CoseHeader();
header.set_alg(Alg.aes_mac_256_128, true, false);
header.set_iv(Buffer.from('89f52f65a1c580933b5261a7', 'hex'), true, false);

// Prepare CoseMAC
let mac = CoseMessage.new_mac();
mac.header = header;
mac.payload = msg;

let key_ecdh_send = new CoseKey();
key_ecdh_send.bytes = Buffer.from("A6200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF01020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65", "hex");
key_ecdh_send.decode();

let key_ecdh_rec = new CoseKey();
key_ecdh_rec.bytes = Buffer.from("A52001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E010202423131", "hex");
key_ecdh_rec.decode();

// Add recipient ECDH ephemeral
let recipient_eph = new CoseAgent();

header = new CoseHeader();
header.set_alg(Alg.ecdh_es_a128kw, true, false);
header.set_kid(key_ecdh_rec.kid, false, false);
recipient_eph.header = header;

recipient_eph.key(key_ecdh_rec);
recipient_eph.ephemeral_key(key_ecdh_send, true, false);

mac.add_agent(recipient_eph);

// Add recipient ECDH static key
let recipient_static = new CoseAgent();

header = new CoseHeader();
header.set_alg(Alg.ecdh_ss_a128kw, true, false);
header.set_kid(key_ecdh_rec.kid, false, false);
recipient_static.header = header;

recipient_static.key(key_ecdh_rec);
recipient_static.static_key(key_ecdh_send, true, false);

mac.add_agent(recipient_static);

// Add recipient ECDH static KID 
let recipient_skid = new CoseAgent();

header = new CoseHeader();
header.set_alg(Alg.ecdh_ss_a128kw, true, false);
header.set_kid(key_ecdh_rec.kid, false, false);
recipient_skid.header = header;

recipient_skid.key(key_ecdh_rec);
recipient_skid.static_kid(key_ecdh_send.kid, key_ecdh_send, true, false);

mac.add_agent(recipient_skid);

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

// Prepare sender public key
let key_ecdh_send = new CoseKey();
key_ecdh_send.bytes = Buffer.from("A5200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C01020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65", "hex");
key_ecdh_send.decode();

// Prepare receiver private key
let key_ecdh_rec = new CoseKey();
key_ecdh_rec.bytes = Buffer.from("A62001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3010202423131", "hex");
key_ecdh_rec.decode();

// Prepare CoseMAC with the cose-mac bytes
let verify = CoseMessage.new_mac();
verify.bytes = Buffer.from("d8618552a201181a054c89f52f65a1c580933b5261a7a054546869732069732074686520636f6e74656e742e502a0e524fed1d0742b59c1c15cd519ba983835850a201381c20a4200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c0102a10442313158286b10f4e2b8a95c7b23ebd253d79b5f658e895ffd5edcaea274cf416ef1c24820f6425ae5effc1f1f835877a201381f21a5200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c01020258246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65a1044231315828effd0914890f90b6b6cf99533fcb6726a42b92661bc7594ef78cc8083b328580372503cea33967c483582ba201381f2258246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65a104423131582890d7d1cadeb712aa7426e7a7b9ad6554c1e5c79ebfe974c96b64f275c3f3e9fe09aee3ea5b7bc4f1", "hex");

// Init decoding
verify.init_decoder(null);

// go through all agents
for (let i = 0; i < verify.agents.length; i++) {

  // If ephemeral
  if (verify.agents[i].header.alg == Alg.ecdh_es_a128kw) {
    
    verify.set_agent_key(i, key_ecdh_rec);
    let payload = verify.decode(null, i);

  // if static
  } else if (verify.agents[i].header.alg == Alg.ecdh_ss_a128kw) {

    // if static kid 
    if (verify.agents[i].header.static_kid) {

      verify.set_agent_key(i, key_ecdh_rec);
      verify.set_ecdh_key(i, key_ecdh_send);
      let payload = verify.decode(null, i);

    // if static key
    } else {

      verify.set_agent_key(i, key_ecdh_rec);
      let payload = verify.decode(null, i);
    }
  }
}

```

## Counter Signature

Encode/decode cose-sign with counter signature.

### Encode Counter Signature

```js
var {
  CoseKey,
  CoseMessage,
  CoseHeader,
  CoseAgent,
  Alg,
  Kty,
  Crv,
} = require('cose-w');

let msg = Buffer.from('This is the content.', 'utf8');

// Decode cose-key
let key = new CoseKey();
key.bytes = Buffer.from("A601020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF", "hex");
key.decode();

// Prepare CoseSign
let sign = CoseMessage.new_sign();
sign.payload = msg;

let header = new CoseHeader();
header.set_alg(Alg.es256, true, false);
header.set_kid(key.kid, true, false);
sign.header = header;

sign.key(key);

// Generate signature
sign.secure_content(null);

key.bytes = Buffer.from("A60102024231312001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3", "hex");
key.decode();

// Prepare counter signer
let counter = CoseAgent.new_counter_sig();
header = new CoseHeader();
header.set_kid(key.kid, true, false);
header.set_alg(Alg.es256, true, false);
counter.header = header;

counter.key(key);

// Add counter signature to cose-sign1
sign.counter_sig(null, counter);
sign.add_counter_sig(counter);

// Encode the cose-sign1 message
let bytes = sign.encode(true);
```
### Decode Counter Signature

```js
var {
  CoseKey,
  CoseMessage,
  Alg,
  Kty,
  Crv,
} = require('cose-w');
let key = new CoseKey();
key.bytes = Buffer.from("A601020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF", "hex");
key.decode();

// Prepare CoseSign with the cose-sign1 bytes
let verify = CoseMessage.new_sign();
verify.bytes = Buffer.from("d284582aa201260458246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65a1078347a2044231310126a0584043e4f6cb352d4fc0942b129e76cdf89690fe2a7a2a5d015abac74968c72b22064126ea3addec92c6ba5257be4295e631f34478f1d7a80be3ac832bd714a39cee54546869732069732074686520636f6e74656e742e58408c6d7a58caa8e23ad509ba291cb17689d61e4ad96a51b4a76d46785655df118cc4137815606d983e0bc55ab45f332aebfef85d4c50965269fc90de5651235ba1", "hex");

// Init decoding
verify.init_decoder(null);

verify.key(key);

// Verify signature
let payload = verify.decode(null, null);

key.bytes = Buffer.from("A60102024231312001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3", "hex");
key.decode();

// Get counter signer and verify counter signature
let i = verify.counter(key.kid, null)[0];
verify.set_counter_key(i, null, key);
verify.counters_verify(null, i, null);
```

## Counter Signature (Externally signed/verified)

Encode/decode cose-mac with counter signature externally signed/verified.

### Encode (externally signed)

```js
let msg = Buffer.from('This is the content.', 'utf8');

// Decode cose-key
let key = new CoseKey();
key.bytes = Buffer.from("A601020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF", "hex");
key.decode();

// Prepare CoseSign
let sign = CoseMessage.new_sign();
sign.payload = msg;

let header = new CoseHeader();
header.set_alg(Alg.es256, true, false);
header.set_kid(key.kid, true, false);
sign.header = header;

sign.key(key);

// Generate signature
sign.secure_content(null);

// Prepare counter signer
let counter = CoseAgent.new_counter_sig();
header = new CoseHeader();
header.set_kid(key.kid, true, false);
header.set_alg(Alg.es256, true, false);
counter.header = header;

// Get the COSE struct to sign externally
let to_sign = sign.get_to_sign(null, counter, null);

// Sign externally
let signature = sign_externally_function();

// Add the signature to the counter signer
counter.add_signature(payload);

// Add the counter signer to the cose_sign message
sign.add_counter_sig(counter);

// Encode the cose-sign1 message
let bytes = sign.encode(true);
```

### Decode (externally verified)

```js
let key = new CoseKey();
key.bytes = Buffer.from("A601020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF", "hex");
key.decode();

// Prepare CoseSign with the cose-sign1 bytes
let verify = CoseMessage.new_sign();
verify.bytes = Buffer.from("d284582aa201260458246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65a1078347a2044231310126a0584043e4f6cb352d4fc0942b129e76cdf89690fe2a7a2a5d015abac74968c72b22064126ea3addec92c6ba5257be4295e631f34478f1d7a80be3ac832bd714a39cee54546869732069732074686520636f6e74656e742e58408c6d7a58caa8e23ad509ba291cb17689d61e4ad96a51b4a76d46785655df118cc4137815606d983e0bc55ab45f332aebfef85d4c50965269fc90de5651235ba1", "hex");

// Init decoding
verify.init_decoder(null);

verify.key(key);

// Verify signature
let payload = verify.decode(null, null);

// Get counter signer and verify counter signature
let i = verify.counter(key.kid, null)[0];

// Get the COSE struct to verify with the signature
let to_verify = verify.get_to_verify(null, i, null);

let signature = verify.header.counters[i].payload;

// Verify the function externally
verify_externally_function();
```
