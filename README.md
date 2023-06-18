# cose-w

 WebAssembly COSE [RFC 8152](https://tools.ietf.org/html/rfc8152) library to encode/decode COSE messages in JS.

# COSE 

COSE is a concise binary data format that protects the payload of the message with a set of cryptographic operations.

The COSE [RFC 8152](https://tools.ietf.org/html/rfc8152) specifies the following 6 types of COSE messages:

- **cose-sign1**: A digitally signed COSE message with a single signer.
- **cose-sign**: A digitally signed COSE message with a signers bucket.
- **cose-encrypt0**: An encrypted COSE message with a single recipient.
- **cose-encrypt**: An encrypted COSE message with a recipients bucket.
- **cose-mac0**: A MAC tagged COSE message with a single recipient.
- **cose-encrypt**: A MAC tagged COSE message with a recipients bucket.

# Examples

The following examples, demonstrate how to encode and decode the basic COSE messages (cose-sign1, cose-encrypt0, cose-mac0), examples of other use cases and cose message types
can be found in the respective documentation.

## cose-sign1

```js
// Message to sign, "This is the content."
let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare cose-key
let key = new CoseKey();
key.kty(Kty.ec2);
key.alg(Alg.es256);
key.crv(Crv.p_256);
key.x(Buffer.from('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', 'hex'));
key.y(Buffer.from('20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e', 'hex'));
key.d(Buffer.from('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3', 'hex'));
key.key_ops([KeyOp.sign, KeyOp.verify]);

// Prepare cose-sign1 header
let header = new CoseHeader();
header.alg(Alg.es256, true, false);
header.kid([49, 49], true, false);

// Generate CoseSign and encode the cose-sign1 final message
let signer = new CoseSign();
signer.add_header(header);
signer.payload(msg);
signer.key(key);
signer.gen_signature(null);
signer.encode(true);

// Prepare CoseSign with the cose-sign1 bytes
let verify = new CoseSign();
verify.set_bytes(signer.get_bytes());

// Init decoding and add key
verify.init_decoder(null);
verify.key(key);

// Verify cose-sign1
verify.decode(null);
```

## cose-encrypt0

```js
// Message to encrypt, "This is the content."
let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare cose-key
let key = new CoseKey();
key.kty(Kty.symmetric);
key.alg(Alg.chacha20);
key.k(Buffer.from('849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188', 'hex'));
key.key_ops([KeyOp.encrypt, KeyOp.decrypt]);

// Prepare cose-encrypt0 header
let header = new CoseHeader();
header.alg(Alg.chacha20, true, false);
header.iv(Buffer.from('89f52f65a1c580933b5261a7', 'hex'), true, false);

// Generate CoseEncrypt and encode the cose-encrypt0 final message
let mac = new CoseEncrypt();
mac.add_header(header);
mac.payload(msg);
mac.key(key);
mac.gen_ciphertext(null);
mac.encode(true);

// Prepare CoseEncrypt with the cose-encrypt0 bytes
let dec = new CoseEncrypt();
dec.set_bytes(mac.get_bytes());

// Init decoding and add key
dec.init_decoder(null);
dec.key(key);

// Decrypt and verify cose-encrypt0 message
let resp= dec.decode(null);
assert.deepEqual(new Buffer.from(resp).toString(), msg.toString());
```

## cose-mac0

```js
// Message to MAC, "This is the content."
let msg = Buffer.from('546869732069732074686520636F6E74656E742E', 'hex');

// Prepare cose-key
let key = new CoseKey();
key.kty(Kty.symmetric);
key.alg(Alg.aes_mac_256_128);
key.k(Buffer.from('849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188', 'hex'));
key.key_ops([KeyOp.mac, KeyOp.mac_verify]);

// Prepare cose-mac0 header
let header = new CoseHeader();
header.alg(Alg.aes_mac_256_128, true, false);

// Generate CoseMAC and encode the cose-mac0 final message
let mac = new CoseMAC();
mac.add_header(header);
mac.payload(msg);
mac.key(key);
mac.gen_tag(null);
mac.encode(true);

// Prepare CoseMAC with the cose-mac0 bytes
let verify = new CoseMAC();
verify.set_bytes(mac.get_bytes());

// Init decoding and add key
verify.init_decoder(null);
verify.key(key);

// Verify cose-mac0 tag
verify.decode(null);
```

# License

This project, cose-w, is licensed by the MIT License.

# Note

This project is under development and it has not been tested yet.
