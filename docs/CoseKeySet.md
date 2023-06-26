# COSE keys documentation

## Getters
- `bytes`: final encoded message.

## Methods 

- `set_bytes(bytes: Vec<u8>)`: Set the COSE key bytes to decode.
- `add_key(key: Cosekey)`: Add COSE key to key set. 
- `encode()`: Encode COSE key set. 
- `decode()`: Decode COSE key set. 
- `get_key(kid: Vec<u8>)`: Get COSE key from key set with the respective KID. 
