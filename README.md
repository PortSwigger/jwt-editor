# JWT Editor

JWT Editor is a Burp Suite extension for editing, signing, verifying, encrypting and decrypting JSON Web Tokens (JWTs).

It provides automatic detection and in-line editing of JWTs within HTTP requests/responses, signing and encrypting of tokens and automation of several well-known attacks against JWT implementations.

It was written originally by Fraser Winterborn, formerly of BlackBerry Security Research Group. The original source code can be found [here](https://github.com/blackberry/jwt-editor).


## Modifications from Fraser Winterborn version
* Payload processing rule to support fuzzing within JWS
* Insertion point provider for JWS header parameters
* JWT highlighting within websocket messages
* Update to Java 17 and PortSwigger's new Montoya API
* Add ability to enable/disable JWT highlighting within proxied messages and to change highlight color
* Add ability to inject Collaborator payloads into x5u and jku headers
* Fix issue where invalid JWS's not recognised
* Add ability to export keys as a JWK set
* Add ability to sign with empty keys (CVE-2019-20933)
* Add ability to sign with psychic signatures (CVE-2022-21449)
* Color sections of serialized JWT differently 
* Remove standalone mode
* Minor bug fixes and enhancements

## Build Instructions
* Ensure that Java JDK 17 or newer is installed
* From root of project, run the command `./gradlew jar`
* This should place the JAR file `jwt-editor-2.0.1.jar` within the `build/libs` directory
* This can be loaded into Burp by navigating to the `Extensions` tab, `Installed` sub-tab, clicking `Add` and loading the JAR file
* This BApp is using the newer Montoya API so it's best to use the latest version of Burp (try the earlier adopter channel if there are issues with the latest stable release)

## Keys View
<img src="gitimg/keys.png" width="600"/>

The `Keys View` allows cryptographic keys to be imported/exported, generated and converted between the JWK and PEM formats.

<img src="gitimg/key_view.png" width="400"/>

Keys are persisted within a `.jwt-editor` folder within the user's home directory for Standalone mode, or within the Burp Suite user options when used as a Burp extension.

## Editor View
<img src="gitimg/editor.png" width="600"/>

The `Editor View` allows modification of the JWTs loaded into the tool via either the `Entry View` in Standalone mode, or Burp Suite's HTTP Request/Response view in the Proxy, History and Repeater tools.

The editor view has two layouts, `JWS` and `JWE`, which are selected depending on whether a JSON Web Signature or JSON Web Encryption is detected.

### Editable Fields

A JSON text editor is provided to edit each of the JWS and JWE components that contain JSON content:

* JWS Header
* JWS Payload
* JWE Header

A hex editor is provided to alter each of the JWS and JWE fields that contain binary content:

* JWS Signature
* JWE Encrypted Key
* JWE Initialization Vector
* JWE Ciphertext
* JWE Authentication Tag

### Sign
`Sign` presents a signing dialog that can be used to update the Signature by signing the JWS Header and Payload using a key from the `Keys View` that has signing capabilities

<img src="gitimg/sign.png" width="400"/>

### Verify

`Verify` will attempt to verify the Signature of a JWS Header and Payload using any key that is capable of verification from the `Keys View`. A dialog will be presented with the result of the verification operation.

<img src="gitimg/verify.png" width="600"/>

### Encrypt

`Encrypt` presents an encryption dialog that can be used to encrypt the JWS Header, Payload and Signature fields to produce a JWE using a key from the `Keys View` that is capable of encryption.

Encrypting a JWS will change the editor mode to `JWE` to allow modification of the JWE components after encryption.

<img src="gitimg/encrypt.png" width="400"/>

### Decrypt
`Decrypt` will attempt to use the keys configured in the `Keys View` that are capable of decryption to decrypt the content of a JWE to produce a JWS.

Decrypting a JWE will change the editor mode to `JWS` to allow modification of the JWS components after decryption.

### Attack
The `Attack` option implements three well-known attacks against JSON Web Signatures:

* Embedded JWK
* 'none' Signing Algorithm
* HMAC Key Confusion

These are described in more detail below.

### Format JSON
The `Format JSON` option on JSON fields automatically corrects the spacing and indentation of the JSON document.

### Compact JSON
The handling of whitespace and newlines is important for a JSON Web Signature, as the encoded bytes of the JSON document are used to form the signature field. The `Compact JSON` option is used to control how the content of the JSON fields will be serialized.

When enabled, whitespace and newlines will be automatically stripped from the JSON document before serialization. When disabled, whitespace and newlines will be preserved.

This option is automatically enabled if it is detected that the original JWT did not contain whitespace or newlines.

# Supported Algorithms

The following JWK types are supported:

* Octet Sequence (OCT) - AES/HMAC
* RSA
* Elliptic-Curve (ECC) - P-256, P-384, P-521
* Octet Key Pair (OKP) - x25519, x448, ed25519, ed448
* Passwords (PBES)

The following JWS/JWE algorithms are supported:

### Signing

* HS256
* HS384
* HS512
* RS256
* RS512
* PS384
* PS256
* PS512
* PS384
* ES256
* ES384
* ES512
* EdDSA

### Encryption

#### Key Encryption

* dir(ect)
* RSA1_5
* RSA-OAEP
* RSA-OAEP-256
* A128KW
* A192KW
* A256KW
* ECDH-ES
* ECDH-ES+A128KW
* ECDH-ES+A192KW
* ECDH-ES+A256KW
* A128GCMKW
* A192GCMKW
* A256GCMKW
* PBES2-HS256+A128KW
* PBES2-HS384+A192KW
* PBES2-HS512+A256KW

#### Content Encryption

* A128GCM
* A192GCM
* A256GCM
* A128CBC-HS256
* A192CBC-HS384
* A256CBC-HS512
* A128CBC+HS256
* A256CBC+HS512

# Attacks

The JWT Editor automates three common attacks against JSON Web Signatures.

## 'none' Signing Algorithm

The value 'none' is defined in the JWA standard as an accepted signing algorithm for JWS. This is intended for use where an out-of-band method has been used to already verify the integrity of the JWS. However, some libraries have been found to treat this as a valid algorithm when processing a JWS.

This attack automates stripping of the signature value from a JWS.

## HMAC Key Confusion

Each algorithm within JWS has a required key type (RSA, EC, OKP or oct). A vulnerability has been identified within JOSE implementations where the key type provided in a JWS header does not match that of the algorithm specified. An attacker that provides a symmetric HS256/384/512 'alg' value with a asymmetric 'kty' (EC, RSA, OKP) value may cause the validating library to use the asymmetric public key as the symmetric key input to a HMAC signature validation. As the public key is known to the attacker, the attacker can use the public key as the input to their HMAC signature and forge a signature which is accepted by the server.

The tool implements this attack using the steps outlined at https://www.nccgroup.com/ae/about-us/newsroom-and-events/blogs/2019/january/jwt-attack-walk-through/.

## Embedded JWK

JWS defines a 'jwk' field within the Header which is used for the ECDH-ES algorithms as a method of transporting the public key to the recipient. However, this field has been mistakenly used by library implementations as a source of the key for signature verification. By creating a new key, embedding the key for verification within the header, and then signing the JWS Payload, an attacker is able to produce arbitrary JWT payloads.
