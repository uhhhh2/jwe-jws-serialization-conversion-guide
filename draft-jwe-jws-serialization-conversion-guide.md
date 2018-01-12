---
title: "JWE and JWS Serialization Conversion Guide"
abbrev: joseconv
docname: draft-jwe-jws-serialization-conversion-guide-latest
category: info
kw: Internet-Draft
ipr: "trust200902"

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: L. Widick
    name: Logan Widick
    email: logan.widick@gmail.com

--- abstract

JSON Web Signature (JWS) and JSON Web Encryption (JWE) are standards for signing and encrypting content using JSON-based formats. However, multiple types of serializations exist for JWS and JWE. Not all existing JWS and JWE implementations can read all types of serializations or allow application developers to control the types of serializations produced. This is a guide intended to help application developers identify and convert between the different types of  JWS and JWE serializations themselves as needed to implement JWS and JWE-based applications. 

--- middle

# Introduction 

JSON Object Signing and Encryption (JOSE) is a set of IETF standards for signing and encrypting JavaScript Object Notation (JSON) {{!RFC7159}} objects. Some standards in this set, such as JSON Web Signature (JWS) {{!RFC7515}} and  JSON Web Encryption (JWE) {{!RFC7516}}, can be serialized in multiple formats. For example, JWS has a "Compact" serialization that is designed for one signer and outputs a string that can be included in a Uniform Resource Locator (URL), a "Flattened JSON" serialization that is designed for one signer and results in a JSON object, and a "General JSON" serialization that is designed for multiple signers and results in a JSON object. Similarly, JWE has a "Compact" serialization that is designed for one recipient and outputs a string that can be included in a Uniform Resource Locator (URL) {{!RFC3986}}, a "Flattened JSON" serialization that is designed for one recipient and results in a JSON object, and a "General JSON" serialization that is designed for multiple recipients and results in a JSON object.

Not all JOSE implementations support all JWE and JWS serialization formats, or allow programmers to select a specific serialization format. Consequently, implementations of protocols such as Automated Certificate Management Environment (ACME) {{?I-D.ietf-acme-acme}} that use the JOSE standards may need to support all serialization formats. A programmer that develops an implementation of such a protocol may need to write code to convert received JWS or JWE messages into the serialization format used by the programmer's preferred JOSE library, and to convert serializations produced by the JOSE library into the serializations required by the protocol. 

The purpose of this document is to serve as a guide for developers that need to identify and convert between the different JWS and JWE serialization formats. Although this document was originally intended for programmers implementing ACME clients and servers, this document should apply to programmers implementing other standards as well. Consequently, this document has been expanded to include things that one might not encounter in ACME, such as unencoded and/or detached payloads, unprotected headers, and JWE messages. 

# Notation Conventions 

- `base64url_encode(OCTETS)`: This function takes in some `OCTETS` and returns a string that represents the base64url encoding of said octets as described in  Section 5 of RFC 4648 {{!RFC4648}}.
- `base64url_decode(STRING)`: This function takes in a `STRING` that represents the base64url encoding of some octets. This function decodes the string and returns the octets as described in Section 5 of RFC 4648 {{!RFC4648}}.
- `utf8_encode(STRING)`: This function returns octets of the UTF-8 {{!RFC3629}} encoding of `STRING`. 
- `utf8_decode(OCTETS)`: This function takes in some` OCTETS` and uses UTF-8 to decode said `OCTETS`into a `STRING`. 

# Distinguishing Between JSON Web Signature (JWS) and JSON Web Encryption (JWE) Objects

Some information on distinguishing between JSON Web Signature (JWS) and JSON Web Encryption (JWE) Objects is provided in Section 9 of {{!RFC7516}}. An overview of this information is included here as well for reference. 

- JWS Compact Serializations have three parts separated by periods, while JWE Compact Serializations have five parts separated by periods. 
- JWS JSON Serializations and JWE JSON Serializations have different field names:
  - JWS Only
    - `payload`
    - `signature` 
    - `signatures` 
  - JWE Only
    - `ciphertext`
    - `aad`
    - `iv`
    - `tag`
    - `recipient`
    - `unprotected`

# JSON Web Signature (JWS) Serialization Format Conversion

## How to Detect the JWS Serialization Format

### Compact Serialization 

This is a string separated into three parts, using the period (`.`) as a delimiter. The second part may be empty, indicating a detached payload as described in Appendix F of {{!RFC7515}}. The first and third parts will always consist of characters from the "URL and Filename Safe Alphabet" from Section 5 of {{!RFC4648}}. Unless the JWS Unencoded Payload option {{!RFC7797}} is used, the second part, if present, will also consist  of characters from the URL and Filename Safe Alphabet from Section 5 of {{!RFC4648}}.

### Flattened JSON Serialization

This is a JSON object that has a `signature` field. The value of this field is a JSON string whose value is `base64url_encode(OCTETS)` for some `OCTETS`. 

### General JSON Serialization 

This is a JSON object that has a `signatures` field. The value of this field is an array of JSON objects. 

## How to Convert Between the JWS Serialization Formats

### Compact Serialization to Flattened JSON Serialization

1. Split the string using the period (`.`) as the delimiter to obtain the following:
   1. `Base64URL_UTF8_ProtHdr`: An encoded version of the JWS Protected Header. If `JWS_ProtHdr` is the JWS Protected Header object serialized to a string, `Base64URL_UTF8_ProtHdr`  is `base64url_encode(utf8_encode(JWS_ProtHdr)`.
   2. `ProvidedPayload`: The provided payload.
   3. `BASE64URL_Signature`: An encoded version of the JWS Signature. If `JWS_Sig` is the raw octets of the JWS Signature, then `BASE64URL_Signature` is `base64url_encode(JWS_Sig)`.
2. Check that three parts were extracted. Note that the second part (`ProvidedPayload`) may be empty. 
3. Load the result of `utf8_decode(base64url_decode(Base64URL_UTF8_ProtHdr))` into a JSON object called `JWS_ProtHdr_JSON`.
4. Determine if the `ProvidedPayload` is detached (Appendix F of {{!RFC7515}}), encoded and non-detached, or unencoded {{!RFC7797}} and non-detached. 
   1. If the`ProvidedPayload` is empty, then it is detached. 
   2. If `JWS_ProtHdr_JSON` contains a `b64` field whose value is set to `false`, `ProvidedPayload` is unencoded and non-detached. 
   3. Otherwise, `ProvidedPayload` is encoded and non-detached. 
5. Check that `ProvidedPayload` is valid.
   1. If the `ProvidedPayload` is detached, continue to the next step.
   2. If the `ProvidedPayload` is encoded and non-detached, check that it is equal to `base64url_encode(OCTETS)` for some `OCTETS`. 
   3. If the `ProvidedPayload` is unencoded, make sure that it can be represented as a UTF-8 encoded JSON string. 
6. Check that `BASE64URL_Signature` is equal to `base64url_encode(OCTETS)` for some `OCTETS`. 
7. Prepare `ConvertedPayload`, the appropriate JSON string representation of `ProvidedPayload`.
   1. If the `ProvidedPayload` is detached, then `ConvertedPayload` is an empty JSON string. 
   2. If the `ProvidedPayload` is encoded and non-detached, then the value of `ConvertedPayload` is the same as `ProvidedPayload` .
   3. If the `ProvidedPayload` is unencoded and non-detached, let `ConvertedPayload` be a JSON string such that `utf8_encode(ConvertedPayload) == ProvidedPayload`. Make sure this string doesn't contain unassigned Unicode code points. 
8. Create a JSON object. This will be the JWS Flattened Serialization. Put the following properties inside this object: 
   1. `protected`: Set this to the value of `Base64URL_UTF8_ProtHdr`.
   2. `payload`: Set this to the value of `ConvertedPayload`.
   3. `signature`: Set this to the value of `BASE64URL_Signature`.

### Compact Serialization to General JSON Serialization

1. Split the string using the period (`.`) as the delimiter to obtain the following:
   1. `Base64URL_UTF8_ProtHdr`: An encoded version of the JWS Protected Header. If `JWS_ProtHdr` is the JWS Protected Header object serialized to a string, `Base64URL_UTF8_ProtHdr`  is `base64url_encode(utf8_encode(JWS_ProtHdr)`.
   2. `ProvidedPayload`: The provided payload.
   3. `BASE64URL_Signature`: An encoded version of the JWS Signature. If `JWS_Sig` is the raw octets of the JWS Signature, then `BASE64URL_Signature` is `base64url_encode(JWS_Sig)`.
2. Check that three parts were extracted. Note that the second part (`ProvidedPayload`) may be empty. 
3. Load the result of `utf8_decode(base64url_decode(Base64URL_UTF8_ProtHdr))` into a JSON object called `JWS_ProtHdr_JSON`.
4. Determine if the `ProvidedPayload` is detached (Appendix F of {{!RFC7515}}), encoded and non-detached, or unencoded {{!RFC7797}} and non-detached. 
   1. If the`ProvidedPayload` is empty, then it is detached. 
   2. If `JWS_ProtHdr_JSON` contains a `b64` field whose value is set to `false`, `ProvidedPayload` is unencoded and non-detached. 
   3. Otherwise, `ProvidedPayload` is encoded and non-detached. 
5. Check that `ProvidedPayload` is valid.
   1. If the `ProvidedPayload` is detached, continue to the next step.
   2. If the `ProvidedPayload` is encoded and non-detached, check that it is equal to `base64url_encode(OCTETS)` for some `OCTETS`. 
   3. If the `ProvidedPayload` is unencoded, make sure that it can be represented as a UTF-8 encoded JSON string. 
6. Check that `BASE64URL_Signature` is equal to `base64url_encode(OCTETS)` for some `OCTETS`. 
7. Prepare `ConvertedPayload`, the appropriate JSON string representation of `ProvidedPayload`.
   1. If the `ProvidedPayload` is detached, then `ConvertedPayload` is an empty JSON string. 
   2. If the `ProvidedPayload` is encoded and non-detached, then the value of `ConvertedPayload` is the same as `ProvidedPayload` .
   3. If the `ProvidedPayload` is unencoded and non-detached, let `ConvertedPayload` be a JSON string such that `utf8_encode(ConvertedPayload) == ProvidedPayload`. Make sure this string doesn't contain unassigned Unicode code points. 
8. Create a JSON object. This will be the JWS General Serialization. Put the following properties inside this object: 
   1. `payload`: Set this to the value of `ConvertedPayload`.
   2. `signatures`: This is an array of JSON objects. Insert a JSON object with the following fields into this array:
      1. `protected`: Set this to the value of `Base64URL_UTF8_ProtHdr`.
      2. `signature`: Set this to the value of `BASE64URL_Signature`.

### Flattened JSON Serialization to Compact Serialization

This procedure discards the JWS Unprotected Header (the `header` field of the Flattened JSON Serialization) because this field is not supported in the Compact Serialization. 

1. Extract the values of the following fields from the Flattened JSON Serialization:
   1. `protected`
   2. `payload` (if present)
   3. `signature`
2. Load the result of `utf8_decode(base64url_decode(protectedValue))` into a JSON object called `JWS_ProtHdr_JSON`, where `protectedValue` is the value of the `protected`  field in the Flattened JSON Serialization.
3. Determine if `ProvidedPayload`, the value of the `payload` field in the Flattened JSON Serialization, is detached, encoded and non-detached, or unencoded and non-detached.
   1. If the`ProvidedPayload` is empty, then it is detached. 
   2. If `JWS_ProtHdr_JSON` contains a `b64` field whose value is set to `false`, `ProvidedPayload` is unencoded and non-detached. 
   3. Otherwise, `ProvidedPayload` is encoded and non-detached. 
4. Check that `ProvidedPayload` is valid.
   1. If the `ProvidedPayload` is detached, continue to the next step.
   2. If the `ProvidedPayload` is encoded and non-detached, check that it is equal to `base64url_encode(OCTETS)` for some `OCTETS`. 
   3. If the `ProvidedPayload` is unencoded, make sure that it does not contain periods ('.'), and that it only contains ASCII characters suitable for the specific application. 
5. Check that `signatureValue`, the value of the `signature` field, is equal to `base64url_encode(OCTETS)` for some `OCTETS`. 
6. Prepare `ConvertedPayload`, the appropriate JSON string representation of `ProvidedPayload`.
   1. If the `ProvidedPayload` is detached, then `ConvertedPayload` is an empty JSON string. 
   2. If the `ProvidedPayload` is encoded and non-detached, then the value of `ConvertedPayload` is the same as `ProvidedPayload` .
   3. If the `ProvidedPayload` is unencoded and non-detached, let `ConvertedPayload` be the ASCII characters of `ProvidedPayload`.
7. The Compact Serialization is `protectedValue + '.' + ConvertedPayload + '.' + signatureValue `.

### Flattened JSON Serialization to General JSON Serialization

1. Extract the values of the following fields from the Flattened JSON Serialization:
   1. `protected`
   2. `header` (if present)
   3. `payload` (if present)
   4. `signature`
2. Create a JSON object. This will be the General JSON Serialization. Put the following properties into this object:
   1. `payload`: Set this to the value of the `payload` field extracted from the Flattened JSON Serialization. 
   2. `signatures`: This is an array of JSON objects. Insert a JSON object with the following fields into this array:
      1. `protected`: Set this to the value of the `protected` field extracted from the Flattened JSON Serialization. 
      2. `header`: Set this to the value of the `header` field extracted from the Flattened JSON Serialization. 
      3. `signature`: Set this to the value of the `signature` field extracted from the Flattened JSON Serialization. 

### General JSON Serialization to Compact Serialization

This procedure will result in multiple Compact Serializations because the Compact Serialization format doesn't support multiple signers. 

1. Extract the value of the `payload` field of the General JSON Serialization. 
2. For each object in the `signatures` array of the General JSON Serialization:
   1. Extract the values of the following fields:
      1. `protected`
      2. `signature`
   2. Load the result of `utf8_decode(base64url_decode(protectedValue))` into a JSON object called `JWS_ProtHdr_JSON`, where `protectedValue` is the value of the `protected`  field extracted above.
   3. Determine if `ProvidedPayload`, the value of the `payload` field in the Flattened JSON Serialization, is detached, encoded and non-detached, or unencoded and non-detached. Note that the classification of `ProvidedPayload` (detached; encoded and non-detached; unencoded and non-detached) MUST be the same for all objects in the `signatures` array of the General JSON serialization.
      1. If the`ProvidedPayload` is empty, then it is detached. 
      2. If `JWS_ProtHdr_JSON` contains a `b64` field whose value is set to `false`, `ProvidedPayload` is unencoded and non-detached. 
      3. Otherwise, `ProvidedPayload` is encoded and non-detached. 
   4. Check that `ProvidedPayload` is valid.
      1. If the `ProvidedPayload` is detached, continue to the next step.
      2. If the `ProvidedPayload` is encoded and non-detached, check that it is equal to `base64url_encode(OCTETS)` for some `OCTETS`. 
      3. If the `ProvidedPayload` is unencoded, make sure that it does not contain periods ('.'), and that it only contains ASCII characters suitable for the specific application. 
   5. Check that `signatureValue`, the value of the `signature` field, is equal to `base64url_encode(OCTETS)` for some `OCTETS`. 
   6. Prepare `ConvertedPayload`, the appropriate JSON string representation of `ProvidedPayload`.
      1. If the `ProvidedPayload` is detached, then `ConvertedPayload` is an empty JSON string. 
      2. If the `ProvidedPayload` is encoded and non-detached, then the value of `ConvertedPayload` is the same as `ProvidedPayload` .
      3. If the `ProvidedPayload` is unencoded and non-detached, let `ConvertedPayload` be the ASCII characters of `ProvidedPayload`.
   7. The Compact Serialization for this object in the General JSON Serialization `signatures` array is `protectedValue + '.' + ConvertedPayload + '.' + signatureValue `.

### General JSON Serialization to Flattened JSON Serialization

This procedure will result in multiple Flattened JSON Serializations because the Flattened JSON Serialization format doesn't support multiple signers. 

1. Extract the value of the `payload` field of the General JSON Serialization. 
2. For each object in the `signatures` array of the General JSON Serialization:
   1. Extract the values of the following fields:
      1. `protected`
      2. `header` (if present)
      3. `signature`
   2. Create a new JSON object that will be the current Flattened JSON Serialization. Copy the values of the following properties into the new JSON object:
      1. `protected`
      2. `header`
      3. `signature`
      4. `payload`

# JSON Web Encryption (JWE) Serialization Format Conversion

## How to Detect the JWE Serialization Format

### Compact Serialization

This is a string separated into five parts, using the period (`.`) as a delimiter. Each part will consist of characters from the URL and Filename Safe Alphabet from Section 5 of {{!RFC4648}}. 

### General JSON Serialization

This is a JSON object with a `recipients` field. The `recipients` field contains an array of objects. Each object in the array could have the following properties:

-  `header` (unprotected content; optional)
-  `encrypted_key`: The symmetric key used for encrypting and authenticating the message. This is encrypted for the specific recipient, and then base64url {{!RFC4648}} encoded.

### Flattened JSON Serialization

This is a JSON object without a `recipients` field. Instead, the contents of objects that would have gone in the `recipients` field are placed directly into the Flattened JSON Serialization. Note that this format can only support one recipient. 

## How to Convert Between the JWE Serialization Formats

### Compact Serialization to Flattened JSON Serialization

1. Split the Compact Serialization into the following parts, using the period (`.`) as the delimiter:
   1. The JWE Protected Header, serialized to a UTF-8 {{!RFC3629}} string that is then Base64URL {{!RFC4648}} encoded.
   2. The Base64URL {{!RFC4648}} encoded JWE Encrypted Key. 
   3. The Base64URL {{!RFC4648}} encoded JWE Initialization Vector.
   4. The Base64URL {{!RFC4648}} encoded JWE Ciphertext.
   5. The Base64URL {{!RFC4648}} encoded JWE Authentication Tag.
2. Create a new JSON object. This will be the Flattened JSON Serialization. Put the following properties in this object:
   1. `protected`: The JWE Protected Header extracted above. Leave it Base64URL encoded.
   2. `encrypted_key`: The JWE Encrypted Key extracted above. Leave it Base64URL encoded.
   3. `iv`: The JWE Initialization Vector extracted above. Leave it Base64URL encoded.
   4. `ciphertext`: The JWE Ciphertext extracted above. Leave it Base64URL encoded.
   5. `tag`: The JWE Authentication Tag extracted above. Leave it Base64URL encoded. 

### Compact Serialization to General JSON Serialization

1. Split the Compact Serialization into the following parts, using the period (`.`) as the delimiter:
   1. The JWE Protected Header, serialized to a UTF-8 {{!RFC3629}} string that is then Base64URL {{!RFC4648}} encoded.
   2. The Base64URL {{!RFC4648}} encoded JWE Encrypted Key. 
   3. The Base64URL {{!RFC4648}} encoded JWE Initialization Vector.
   4. The Base64URL {{!RFC4648}} encoded JWE Ciphertext.
   5. The Base64URL {{!RFC4648}} encoded JWE Authentication Tag.
2. Create a new JSON object. This will be the recipient in the General JSON Serialization. Put the following properties in this object:
   1. `encrypted_key`: The JWE Encrypted Key extracted above. Leave it Base64URL encoded.
3. Create a new JSON object. This will be the Flattened JSON Serialization. Put the following properties in this object:
   1. `protected`: The JWE Protected Header extracted above. Leave it Base64URL encoded.
   2. `iv`: The JWE Initialization Vector extracted above. Leave it Base64URL encoded.
   3. `ciphertext`: The JWE Ciphertext extracted above. Leave it Base64URL encoded.
   4. `tag`: The JWE Authentication Tag extracted above. Leave it Base64URL encoded.
   5. `recipients`: An array of JSON objects. Add the recipient created above to this array. 

### Flattened JSON Serialization to Compact Serialization

The procedure below can be used to convert a Flattened JSON Serialization to a Compact Serialization. The unprotected headers  (both Shared and Per-Recipient) and Additional Authenticated Data (AAD) are skipped because those do not exist in Compact Serializations. 

1. Extract the following fields from the Flattened JSON Serialization:
   1. `protected`: The JWE Protected Header. Leave it Base64URL {{!RFC4648}} encoded.
   2. `encrypted_key`: The JWE Encrypted Key. Leave it Base64URL encoded.
   3. `iv`: The JWE Initialization Vector. Leave it Base64URL encoded.
   4. `ciphertext`: The JWE Ciphertext. Leave it Base64URL encoded.
   5. `tag`: The JWE Authentication Tag. Leave it Base64URL encoded.
   6. `encrypted_key`: The JWE Encrypted Key. Leave it Base64URL encoded.
2. Concatenate the following components together using a period (`.`) as the delimiter to form the Compact Serialization:
   1. The JWE Protected Header extracted above. Leave it Base64URL encoded.
   2. The JWE Encrypted Key extracted above. Leave it Base64URL encoded.
   3. The JWE Initialization Vector extracted above. Leave it Base64URL encoded.
   4. The JWE Ciphertext extracted above. Leave it Base64URL encoded.
   5. The JWE Authentication Tag extracted above. Leave it Base64URL encoded.
   6. The JWE Encrypted Key extracted above. Leave it Base64URL encoded.

### Flattened JSON Serialization to General JSON Serialization

The procedure below can be used to convert a Flattened JSON Serialization to a General JSON Serialization. 

1. Extract the following fields from the Flattened JSON Serialization:
   - `protected`: The JWE Protected Header. Leave it Base64URL {{!RFC4648}} encoded.
   - `unprotected`: The JWE Shared Unprotected Header (if present). Leave it as a JSON object. 
   - `iv`: The JWE Initialization Vector. Leave it Base64URL encoded.
   - `aad`The JWE Additional Authenticated Data (if present). Leave it Base64URL encoded.
   - `ciphertext`: The JWE Ciphertext. Leave it Base64URL encoded.
   - `tag`: The JWE Authentication Tag. Leave it Base64URL encoded. 
   - `header`: The JWE Per-Recipient Unprotected Header (if present). Leave it as a JSON object.
   - `encrypted_key`: The JWE Encrypted Key. Leave it Base64URL encoded.
2. Create a new JSON object. This will be the recipient object for the recipient indicated in the Flattened JSON Serialization. Put the following properties in this object:
   - `header`: The JWE Per-Recipient Unprotected Header. Leave it as a JSON object. Only put this field in if it exists in the Flattened JSON Serialization. 
   - `encrypted_key`: The JWE Encrypted Key. Leave it Base64URL encoded.
3. Create a new JSON object. This will be the General JSON Serialization. Put the following properties in this object:
   - `protected`: The JWE Protected Header. Leave it Base64URL {{!RFC4648}} encoded.
   - `unprotected`: The JWE Shared Unprotected Header (if present). Leave it as a JSON object. Only put this field in if it exists in the Flattened JSON Serialization. 
   - `iv`: The JWE Initialization Vector. Leave it Base64URL encoded.
   - `aad`The JWE Additional Authenticated Data. Leave it Base64URL encoded. Only put this field in if it exists in the Flattened JSON Serialization. 
   - `ciphertext`: The JWE Ciphertext. Leave it Base64URL encoded.
   - `tag`: The JWE Authentication Tag. Leave it Base64URL encoded. 
   - `recipients`: The array of recipient objects. Put the recipient object created above in this array.

### General JSON Serialization to Compact Serialization

The procedure below can be used to convert a General JSON Serialization to one or more Compact Serializations. This procedure will produce a Compact Serialization for each recipient in the General JSON Serialization, because a Compact Serialization can only have one recipient. The unprotected headers (both Shared and Per-Recipient) and Additional Authenticated Data (AAD) are skipped because those do not exist in Compact Serializations. 

1. Extract the following fields from the General JSON Serialization:
   - `protected`: The JWE Protected Header. Leave it Base64URL {{!RFC4648}} encoded.
   - `iv`: The JWE Initialization Vector. Leave it Base64URL encoded.
   - `ciphertext`: The JWE Ciphertext. Leave it Base64URL encoded.
   - `tag`: The JWE Authentication Tag. Leave it Base64URL encoded. 
2. For each recipient object in the `recipients` array of the General JSON Serialization, do the following to create a corresponding Compact Serialization:
   1. Extract the following from the recipient object:
      - `encrypted_key`: The JWE Encrypted Key. Leave it Base64URL encoded.
   2. Concatenate the following components together using a period (`.`) as the delimiter to form the Compact Serialization for the recipient object:
      1. The JWE Protected Header extracted above. Leave it Base64URL encoded.
      2. The JWE Encrypted Key extracted above. Leave it Base64URL encoded.
      3. The JWE Initialization Vector extracted above. Leave it Base64URL encoded.
      4. The JWE Ciphertext extracted above. Leave it Base64URL encoded.
      5. The JWE Authentication Tag extracted above. Leave it Base64URL encoded.
      6. The JWE Encrypted Key extracted above. Leave it Base64URL encoded.

### General JSON Serialization to Flattened JSON Serialization

The procedure below can be used to convert a General JSON Serialization to one or more Flattened JSON Serializations. This procedure will produce a Flattened JSON Serialization for each recipient in the General JSON Serialization, because a Flattened JSON Serialization can only have one recipient. 

1. Extract the following fields from the General JSON Serialization:
   - `protected`: The JWE Protected Header. Leave it Base64URL {{!RFC4648}} encoded.
   - `unprotected`: The JWE Shared Unprotected Header (if present). Leave it as a JSON object. 
   - `iv`: The JWE Initialization Vector. Leave it Base64URL encoded.
   - `aad`The JWE Additional Authenticated Data (if present). Leave it Base64URL encoded.
   - `ciphertext`: The JWE Ciphertext. Leave it Base64URL encoded.
   - `tag`: The JWE Authentication Tag. Leave it Base64URL encoded. 
2. For each recipient object in the `recipients` array of the General JSON Serialization, do the following to create the corresponding Flattened JSON Serialization:
   1. Extract the following from the recipient object:
      - `header`: The JWE Per-Recipient Unprotected Header (if present). Leave it as a JSON object.
      - `encrypted_key`: The JWE Encrypted Key. Leave it Base64URL encoded.
   2. Create a new JSON object. This will be the Flattened JSON Serialization for the current recipient. Put the following properties in this object:
      - `protected`: The JWE Protected Header. Leave it Base64URL {{!RFC4648}} encoded.
      - `unprotected`: The JWE Shared Unprotected Header. Leave it as a JSON object. Only put this field in if it exists in the General JSON Serialization. 
      - `iv`: The JWE Initialization Vector. Leave it Base64URL encoded.
      - `aad`The JWE Additional Authenticated Data. Leave it Base64URL encoded.  Only put this field in if it exists in the recipient in the General JSON Serialization. 
      - `ciphertext`: The JWE Ciphertext. Leave it Base64URL encoded.
      - `tag`: The JWE Authentication Tag. Leave it Base64URL encoded. 
      - `header`: The JWE Per-Recipient Unprotected Header. Leave it as a JSON object. Only put this field in if it exists in the recipient in the General JSON Serialization. 
      - `encrypted_key`: The JWE Encrypted Key. Leave it Base64URL encoded.

# Security Considerations

This is a guide for converting between different JWS and JWE serializations. Thus, all security considerations in {{!RFC7515}} and {{!RFC7516}} apply. If programmers need to work with unencoded payloads, the security considerations in {{!RFC7797}} also apply. 

# IANA Considerations

No IANA Considerations.




