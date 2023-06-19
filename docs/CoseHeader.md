# COSE headers documentation

## Getters

- `protected`: array with the protected COSE labels.
- `unprotected`: array with the unprotected COSE labels.
- `crit`: array with the COSE message critical labels.
- `alg`: COSE algorithm.
- `content_type`: COSE content type.
- `kid`: COSE key ID.
- `iv`: Initialization Vector.
- `partial_iv`: Partial Initialization Vector.
- `salt`: salt.
- `party_u_identity`: Party U identity.
- `party_u_nonce`: Party U Nonce.
- `party_u_other`: Party U Other.
- `party_v_identity`: Party V identity.
- `party_v_nonce`: Party V Nonce.
- `party_v_other`: Party V Other.
- `ecdh_key`: ECDH sender key.
- `static_kid`: Static COSE key ID.

When decoding a COSE message, after the function `init_decoding`, all the COSE message parameters will be accessible by the previously listed getters.

## Methods 

The following methods boolean parameter `prot` specify if the label is to be encoded in the protected or unprotected header and  `crit` if the
label is to be included in the COSE "crit" array.

- `set_alg(alg: i32, prot: bool, crit: bool)`: Sets the COSE algorithm.
- `set_kid(kid: Vec<u8>, prot: bool, crit: bool)`: Sets the COSE key ID.
- `set_iv(iv: Vec<u8>, prot: bool, crit: bool)`: Sets the IV.
- `set_partial_iv(partial_iv: Vec<u8>, prot: bool, crit: bool)`: Sets the partial IV.
- `set_salt(salt: Vec<u8>, prot: bool, crit: bool)`: Sets the salt.
- `set_content_type(content_type: u32, prot: bool, crit: bool)`: Sets the content type.
- `set_party_identity(identity: Vec<u8>, prot: bool, crit: bool, u: bool)`: Sets the Party Identity, if `u` is `true` it sets on the Party U, else it sets on Party V.
- `set_party_nonce(nonce: Vec<u8>, prot: bool, crit: bool, u: bool)`: Sets the Party Nonce, if `u` is `true` it sets on the Party U, else it sets on Party V.
- `set_party_other(other: Vec<u8>, prot: bool, crit: bool, u: bool)`: Sets the Party Other, if `u` is `true` it sets on the Party U, else it sets on Party V.
- `ephemeral_key(key: keys::CoseKey, prot: bool, crit: bool)`: Adds the Ephemeral ECDH COSE key.
- `static_key(key: keys::CoseKey, prot: bool, crit: bool)`: Set static ECDH COSE key.
- `set_static_kid(kid: Vec<u8>, key: keys::CoseKey, prot: bool, crit: bool)`: Set static COSE Key ID.
- `set_ecdh_key(key: keys::CoseKey)`: Sets ECDH COSE key (case static KID was used).
