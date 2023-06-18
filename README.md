# cose-w

# COSE 

COSE is a concise binary data format that protects the payload of the message with a set of cryptographic operations.

The COSE [RFC 8152](https://tools.ietf.org/html/rfc8152) specifies the following 6 types of COSE messages:

- **cose-sign1**: A digitally signed COSE message with a single signer.
- **cose-sign**: A digitally signed COSE message with a signers bucket.
- **cose-encrypt0**: An encrypted COSE message with a single recipient.
- **cose-encrypt**: An encrypted COSE message with a recipients bucket.
- **cose-mac0**: A MAC tagged COSE message with a single recipient.
- **cose-encrypt**: A MAC tagged COSE message with a recipients bucket.

# Examples

The following examples, demonstrate how to encode and decode the basic COSE messages (cose-sign1, cose-encrypt0, cose-mac0), examples of other use cases and cose message types
can be found in the respective documentation.

## cose-sign1

### Encode cose-sign1 message

### Decode cose-sign1 message

## cose-encrypt0

### Encode cose-encrypt0 message

### Decode cose-encrypt0 message
## cose-mac0

### Encode cose-mac0 message

### Decode cose-mac0 message

# License

This project, cose-w, is licensed by the MIT License.

# Note

This project is under development and it has not been tested yet.
