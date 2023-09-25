# COSE headers documentation

## Properties

| Name | Type | Getter | Setter | Description |
| ---- | ---- | ------ | ------ | ----------- |
| `protected` | number[] | Yes | No | Array with the protected COSE labels. | 
| `unprotected` | number[] |  Yes | No | Array with the unprotected COSE labels. | 
| `crit` | number[] | Yes | No | Array with the critical COSE labels. | 
| `alg` | number | Yes | No | COSE algorithm. | 
| `content_type` | number | Yes | No | COSE content type. | 
| `kid` | Uint8Array | Yes | No | COSE Key ID. | 
| `iv` | Uint8Array | Yes | No | Initialization Vector. | 
| `partial_iv` | Uint8Array | Yes | No | Partial Initialization Vector. | 
| `salt` | Uint8Array | Yes | No | Salt. | 
| `party_u_identity` | Uint8Array | Yes | No | COSE Party U Identity. | 
| `party_u_nonce` | Uint8Array | Yes | No | COSE Party U Nonce. | 
| `party_u_other` | Uint8Array | Yes | No | COSE Party U Other. | 
| `party_v_identity` | Uint8Array | Yes | No | COSE Party V Identity. | 
| `party_v_nonce` | Uint8Array | Yes | No | COSE Party V Nonce. | 
| `party_v_other` | Uint8Array | Yes | No | COSE Party V Other. | 
| `pub_other` | Uint8Array | Yes | Yes | COSE SuppPubInfo. | 
| `priv_info` | Uint8Array | Yes | Yes | COSE SuppPrivInfo. | 
| `ecdh_key` | Uint8Array | Yes | Yes | COSE ECDH sender key. | 
| `static_kid` | Uint8Array | Yes | No | Static COSE Key ID. | 


When decoding a COSE message, after the function `init_decoding`, all the COSE message parameters will be accessible by the previously listed getters.

## Methods 

The following methods boolean parameter `prot` specifies if the label is to be encoded in the protected or unprotected header and  `crit` if the
label is to be included in the COSE `crit` array.

| Name | Parameters | Returns | Description |
| ---- | ---------- | ------- | ----------- |
| `set_alg(alg: number, prot: bool, crit: bool)` | `alg`: COSE algorithm ID. | --- | Sets the COSE algorithm. | 
| `set_content_type(content_type: number, prot: bool, crit: bool)` | `salt`: COSE Content Type. | --- | Sets the COSE Content Type. | 
| `set_kid(kid: Uint8Array, prot: bool, crit: bool)` | `kid`: COSE Key ID. | --- | Sets the COSE Key ID. | 
| `set_iv(iv: Uint8Array, prot: bool, crit: bool)` | `iv`: Initialization Vector. | --- | Sets the Initialization Vector. | 
| `set_partial_iv(iv: Uint8Array, prot: bool, crit: bool)` | `iv`: Partial Initialization Vector. | --- | Sets the Partial Initialization Vector. | 
| `set_salt(salt: Uint8Array, prot: bool, crit: bool)` | `salt`: Salt. | --- | Sets the Salt. | 
| `set_party_identity(identity: Uint8Array, prot: bool, crit: bool, u: bool)` | `identity`: COSE Party Identity. <br/> `u`: If its Party U or V. | --- | Sets the COSE Party U or V identity. | 
| `set_party_nonce(nonce: Uint8Array, prot: bool, crit: bool, u: bool)` | `nonce`: COSE Party Nonce. <br/> `u`: If its Party U or V. | --- | Sets the COSE Party U or V Nonce. | 
| `set_party_other(other: Uint8Array, prot: bool, crit: bool, u: bool)` | `other`: COSE Party Other. <br/> `u`: If its Party U or V. | --- | Sets the COSE Party U or V Other. | 
| `ephemeral_key(key: CoseKey, prot: bool, crit: bool)` | `key`: COSE Key. | --- | Sets the COSE Ephemeral Key for Direct Key Agreement. | 
| `static_key(key: CoseKey, prot: bool, crit: bool)` | `key`: COSE Key. | --- | Sets the COSE static Key for Direct Key Agreement. | 
| `set_static_kid(kid: Uint8Array, key: CoseKey, prot: bool, crit: bool)` | `kid`: COSE Key ID. <br/> `key`: COSE Key. | --- | Sets the COSE static key, including only the Key ID on the final COSE message. | 

