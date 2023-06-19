# COSE keys documentation

## Getters

- `bytes`: final encoded message.
- `kty`: COSE key type.
- `base_iv`: Base IV.
- `alg`: COSE algorithm.
- `key_ops`: COSE Key Operations array.
- `x`: COSE key X value.
- `y`: COSE key Y value.
- `d`: COSE key D value.
- `k`: COSE key K value.
- `kid`: COSE key ID.
- `crv`: COSE key curve.

## Methods 

The following methods boolean parameter `prot` specify if the label is to be encoded in the protected or unprotected header and  `crit` if the
label is to be included in the COSE "crit" array.

- `set_bytes(&mut self, bytes: Vec<u8>)`: Set the COSE key bytes to decode.
- `set_kty(&mut self, kty: i32)`: Set COSE Key type.
- `set_kid(&mut self, kid: Vec<u8>)`: Set COSE Key ID.
- `set_alg(&mut self, alg: i32)`: Set COSE algorithm.
- `set_key_ops(&mut self, key_ops: Vec<i32>)`: Set COSE Key Operations.
- `set_base_iv(&mut self, base_iv: Vec<u8>)`: Set Base IV.
- `set_crv(&mut self, crv: i32)`: Set COSE key curve.
- `set_x(&mut self, x: Vec<u8>)`: Set COSE key X value. 
- `set_y(&mut self, y: Vec<u8>)`: Set COSE key Y value. 
- `set_d(&mut self, d: Vec<u8>)`: Set COSE key D value. 
- `set_k(&mut self, k: Vec<u8>)`: Set COSE key K value. 
- `decode()`: Decodes the COSE key bytes attribute. 
- `encode()`: Encodes the COSE key into bytes attribute. 
