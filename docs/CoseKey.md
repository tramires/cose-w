# COSE keys documentation

## Properties

| Name | Type | Getter | Setter | Description |
| ---- | ---- | ------ | ------ | ----------- |
| `bytes` | Uint8Array | Yes | Yes | Final encdoed COSE key. | 
| `kty` | number | Yes | Yes | COSE key type. | 
| `base_iv` | Uint8Array | Yes | Yes | Base Initialization Vector. | 
| `alg` | number | Yes | Yes | COSE algorithm ID. | 
| `key_ops` | number[] | Yes | Yes | COSE Key Operations array. | 
| `x` | Uint8Array | Yes | Yes | COSE Key X value. | 
| `y` | Uint8Array | Yes | Yes | COSE Key Y value. | 
| `d` | Uint8Array | Yes | Yes | COSE Key D value. | 
| `k` | Uint8Array | Yes | Yes | COSE key K value. | 
| `n` | Uint8Array | Yes | Yes | RSA modulus n value. | 
| `e` | Uint8Array | Yes | Yes | RSA public exponent e value. | 
| `rsa_d` | Uint8Array | Yes | Yes | RSA private exponent d value. | 
| `p` | Uint8Array | Yes | Yes | Prime factor p of n value. | 
| `q` | Uint8Array | Yes | Yes | Prime factor q of n value. | 
| `dp` | Uint8Array | Yes | Yes | RSA d mod (p - 1) value. | 
| `dq` | Uint8Array | Yes | Yes | RSA d mod (q - 1) value. | 
| `qinv` | Uint8Array | Yes | Yes | RSA CRT coefficient q^(-1) mod p value. | 
| `other` | Uint8Array[] | No | No | Other RSA prime infos, an array. | 
| `ri` | Uint8Array | Yes | Yes | RSA prime factor r\_i of n, where i >= 3. | 
| `di` | Uint8Array | Yes | Yes | RSA d mod (r\_i - 1). | 
| `ti` | Uint8Array | Yes | Yes | RSA CRT coefficient (r\_1 * r\_2 * ... * r_(i-1))^(-1) mod r\_i. | 
| `kid` | Uint8Array | Yes | Yes | COSE Key ID. | 
| `crv` | number| Yes | Yes | COSE Curve ID. | 


## Methods 

| Name | Parameters | Returns | Description |
| ---- | ---------- | ------- | ----------- |
| `encode()` | --- | --- | Encodes the COSE Key. | 
| `decode()` | --- | --- | Decodes the COSE Key. | 
