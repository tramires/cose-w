# CoseAgent documentation

Module to build COSE message agents (signers, recipients and counter signers).

## Constructors:

| Name |  Description |
| ---- | ----------- |
| `new` | Initiates a COSE Agent for signer/recipient. | 
| `new_counter_sig` | Initiates a COSE Agent for counter signatures. | 

## Properties

| Name | Type | Getter | Setter | Description |
| ---- | ---- | ------ | ------ | ----------- |
| `header` | [CoseHeader](CoseHeader.md) | Yes | Yes | COSE header object. | 
| `payload` | `Uint8Array` | Yes | No | Payload of the agent object (ciphertext or signature). |

When decoding a COSE message, after the function `init_decoding`, all the COSE message parameters will be accessible by the previously listed getters.

## Methods 

| Name | Parameters | Returns | Description |
| ---- | ---------- | ------- | ----------- |
| `key(key: CoseKey)` | `key`: COSE key. | --- |  Sets the COSE key to be used. | 
| `ephemeral_key(key: CoseKey, prot: bool, crit: bool)` | `key`: COSE ephemeral key. <br/> `prot`: If its to be included in protected header. <br/> `crit`: If its to be included in `crit` COSE array. | --- | Sets the COSE ephemeral key for Direct Key Agreement. | 
| `static_key(key: CoseKey, prot: bool, crit: bool)` | `key`: COSE static key. <br/> `prot`: If to be included in protected header. <br/> `crit`: If its to be included in `crit` COSE array. | --- | Sets the COSE static key for Direct Key Agreement. | 
| `static_kid(kid: Uint8Array, key: CoseKey, prot: bool, crit: bool)` | `kid`: Static Key ID. <br/> `key`: COSE static key. <br/> `prot`: If to be included in protected header. <br/> `crit`: If its to be included in `crit` COSE array. | --- | Sets the COSE static key for Direct Key Agreement, including only the Key ID on the final COSE message. | 
| `add_signature(signature: Uint8Array)` | `signature`: COSE signature. | --- | Sets the Counter Signature (Method to be used when the counter signature is produced externally. | 

