# Constants

## Alg 

COSE Algorithms.

| Name | Type | Description |
| ---- | ---- | ----------- |
| `es256` | number | ECDSA w/ SHA-256. | 
| `es256k` | number | ECDSA using secp256k1 curve and SHA-256. | 
| `es384` | number | ECDSA w/ SHA-384. | 
| `es512` | number | ECDSA w/ SHA-256. | 
| `eddsa` | number | EdDSA. | 
| `ps256` | number | RSASSA-PSS w/ SHA-256. | 
| `ps384` | number | RSASSA-PSS w/ SHA-384. | 
| `ps512` | number | RSASSA-PSS w/ SHA-512. | 
| `a128gcm` | number | AES-GCM mode w/ 128-bit key, 128-bit tag. | 
| `a192gcm` | number | AES-GCM mode w/ 192-bit key, 128-bit tag. | 
| `a256gcm` | number | AES-GCM mode w/ 192-bit key, 128-bit tag. | 
| `chacha20` | number | ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag. |
| `aes_ccm_16_64_128` | number | AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce. |
| `aes_ccm_16_64_256` | number | AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce. |
| `aes_ccm_64_64_128` | number | AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce. |
| `aes_ccm_64_64_256` | number | AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce. |
| `hmac_256_64` | number | HMAC w/ SHA-256 truncated to 64 bits. |
| `hmac_256_256` | number | HMAC w/ SHA-256. |
| `hmac_384_384` | number | HMAC w/ SHA-384. |
| `hmac_512_512` | number |  	HMAC w/ SHA-512. |
| `aes_mac_128_64` | number | AES-MAC 128-bit key, 64-bit tag. |
| `aes_mac_256_64` | number | AES-MAC 256-bit key, 64-bit tag. |
| `aes_mac_128_128` | number | AES-MAC 128-bit key, 128-bit tag. |
| `aes_mac_256_128` | number | AES-MAC 256-bit key, 128-bit tag. |
| `direct` | number | Direct use of CEK. |
| `direct_hkdf_sha_256` | number | Shared secret w/ HKDF and SHA-256. |
| `direct_hkdf_sha_512` | number | Shared secret w/ HKDF and SHA-512. |
| `direct_hkdf_aes_128` | number | Shared secret w/ AES-MAC 128-bit key. |
| `direct_hkdf_aes_256` | number | Shared secret w/ AES-MAC 256-bit key. |
| `a128kw` | number | AES Key Wrap w/ 128-bit key. |
| `a192kw` | number | AES Key Wrap w/ 192-bit key. |
| `a256kw` | number | AES Key Wrap w/ 256-bit key. |
| `ecdh_es_hkdf_256` | number | ECDH ES w/ HKDF - generate key directly. |
| `ecdh_es_hkdf_512` | number | ECDH ES w/ HKDF - generate key directly. |
| `ecdh_ss_hkdf_256` | number | ECDH SS w/ HKDF - generate key directly. |
| `ecdh_ss_hkdf_512` | number | ECDH SS w/ HKDF - generate key directly. |
| `ecdh_es_a128kw` | number | ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key. |
| `ecdh_es_a192kw` | number | ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key. |
| `ecdh_es_a256kw` | number | ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key. |
| `ecdh_ss_a128kw` | number | ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key. |
| `ecdh_ss_a192kw` | number | ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key. |
| `ecdh_ss_a256kw` | number | ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key. |


## Kty

COSE Key types.

| Name | Type | Description |
| ---- | ---- | ----------- |
| `okp` | number | Octet Key Pair. | 
| `ec2` | number | Elliptic Curve Keys w/ x- and y-coordinate pair. | 
| `rsa` | number | RSA Key. | 
| `symmetric` | number | Symmetric Keys. | 
| `reserved` | number | This value is reserved. | 

## Crv 

COSE Key curves.

| Name | Type | Description |
| ---- | ---- | ----------- |
| `p_256` | number | NIST P-256 also known as secp256r1. | 
| `secp256k1` | number | SECG secp256k1 curve. | 
| `p_384` | number | NIST P-384 also known as secp384r1. | 
| `p_521` | number | NIST P-521 also known as secp521r1. | 
| `x25519` | number | X25519 for use w/ ECDH only. | 
| `x448` | number | X448 for use w/ ECDH only. | 
| `ed25519` | number | Ed25519 for use w/ EdDSA only. | 
| `ed448` | number | Ed448 for use w/ EdDSA only. | 

## KeyOp 

COSE Key operations.

| Name | Type | Description |
| ---- | ---- | ----------- |
| `sign` | number | The key is used to create signatures. | 
| `verify` | number | The key is used for verification of signatures. | 
| `encrypt` | number | The key is used for key transport encryption. | 
| `decrypt` | number | The key is used for key transport decryption. | 
| `mac` | number | The key is used for creating MACs. | 
| `mac_verify` | number | The key is used for validating MACs. | 
| `wrap` | number | The key is used for key wrap encryption. | 
| `unwrap` | number | The key is used for key wrap decryption. | 
| `derive` | number | The key is used for deriving keys. | 
| `derive_bits` | number | The key is used for deriving bits not to be used as a key. |
