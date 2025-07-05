# COSE key set documentation

## Getters

| Name | Type | Getter | Setter | Description |
| ---- | ---- | ------ | ------ | ----------- |
| `bytes` | Uint8Array | Yes | Yes | Final encdoed COSE key set. |
| `keys` | Vec<[CoseKey](CoseKey.md)> | Yes | No| Get all COSE keys from the key set (COPY of the
COSE Keys data). |

## Methods 

| Name | Parameters | Returns | Description |
| ---- | ---------- | ------- | ----------- |
| `decode()` | --- | --- | Decodes the COSE Key. | 
| `add_key(key: CoseKey)` | `key`: COSE key. | --- | Adds a COSE Key to the COSE key set. | 
| `encode()` | --- | --- | Encodes the COSE Key. | 
| `get_key(kid: Uint8Array)` | `kid`: COSE key ID. | number[] | Returns an array of the positions of COSE keys in the COSE key set with the provided Key ID. |


## Key Set Decode Example


```js
var {
  CoseKey,
  CoseKeySet,
} = require('cose-w');

// Encode Key
let key1 = new CoseKey();
key1.bytes = Buffer.from("A601020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF", "hex");
key1.decode();

let key2 = new CoseKey();
key2.bytes = Buffer.from("A60102024231312001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3", "hex");
key2.decode();

let keyset = new CoseKeySet();
keyset.add_key(key1);
keyset.add_key(key2);
keyset.encode();


let keyset_decode = new CoseKeySet();
keyset_decode.bytes = keyset.bytes;
keyset_decode.decode();

key1 = keyset.get_key(key1.kid);
key2 = keyset.get_key(key2.kid);
```
