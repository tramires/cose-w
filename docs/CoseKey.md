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

- `set_bytes(bytes: Vec<u8>)`: Set the COSE key bytes to decode.
- `set_kty(kty: i32)`: Set COSE Key type.
- `set_kid(kid: Vec<u8>)`: Set COSE Key ID.
- `set_alg(alg: i32)`: Set COSE algorithm.
- `set_key_ops(key_ops: Vec<i32>)`: Set COSE Key Operations.
- `set_base_iv(base_iv: Vec<u8>)`: Set Base IV.
- `set_crv(crv: i32)`: Set COSE key curve.
- `set_x(x: Vec<u8>)`: Set COSE key X value. 
- `set_y(y: Vec<u8>)`: Set COSE key Y value. 
- `set_d(d: Vec<u8>)`: Set COSE key D value. 
- `set_k(k: Vec<u8>)`: Set COSE key K value. 
- `decode()`: Decodes the COSE key bytes attribute. 
- `encode()`: Encodes the COSE key into bytes attribute. 
