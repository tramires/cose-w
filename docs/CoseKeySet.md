# COSE key set documentation

## Getters

| Name | Type | Getter | Setter | Description |
| ---- | ---- | ------ | ------ | ----------- |
| `bytes` | Uint8Array | Yes | Yes | Final encdoed COSE key set. |

## Methods 

| Name | Parameters | Returns | Description |
| ---- | ---------- | ------- | ----------- |
| `decode()` | --- | --- | Decodes the COSE Key. | 
| `add_key(key: CoseKey)` | `key`: COSE key. | --- | Adds a COSE Key to the COSE key set. | 
| `encode()` | --- | --- | Encodes the COSE Key. | 
| `get_key(kid: Uint8Array)` | `kid`: COSE key ID. | number[] | Returns an array of the positions of COSE keys in the COSE key set with the provided Key ID. |
