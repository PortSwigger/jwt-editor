/*
Author : Dolph Flynn

Copyright 2022 Dolph Flynn

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package com.blackberry.jwteditor.model.jose;

import com.blackberry.jwteditor.exceptions.EncryptionException;
import com.blackberry.jwteditor.model.keys.Key;
import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;

import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.text.ParseException;

import static com.blackberry.jwteditor.utils.StringUtils.countOccurrences;
import static java.util.Arrays.stream;

public class JWEFactory {
    public static JWE encrypt(JWS jws, Key key, JWEAlgorithm kek, EncryptionMethod cek) throws EncryptionException {
        JWEHeader header = new JWEHeader(kek, cek);

        // Get the encrypter based on the key type
        JWEEncrypter encrypter;
        try {
            encrypter = key.getEncrypter(kek);
        } catch (JOSEException e) {
            throw new EncryptionException("Invalid key type for encryption algorithm");
        }

        // Try to use the BouncyCastle provider, but fall-back to default if this fails
        Provider provider = Security.getProvider("BC");
        if (provider != null) {
            encrypter.getJCAContext().setProvider(provider);
        }

        // Encrypt the JWS with the key to get a set of Base64 encoded parts
        JWECryptoParts jweCryptoParts;
        try {
            jweCryptoParts = encrypter.encrypt(header, jws.serialize().getBytes(StandardCharsets.US_ASCII));
        } catch (JOSEException e) {
            throw new EncryptionException(e.getMessage());
        }

        // Use the returned parts to construct a JWE
        return new JWE(
                jweCryptoParts.getHeader().toBase64URL(),
                jweCryptoParts.getEncryptedKey(),
                jweCryptoParts.getInitializationVector(),
                jweCryptoParts.getCipherText(),
                jweCryptoParts.getAuthenticationTag()
        );
    }

    /**
     * Parse a JWE from compact serialization
     *
     * @param compactJWE JWE in compact serialization form
     * @return a parsed JWE object
     * @throws ParseException if the value is not a valid JWE
     */
    public static JWE parse(String compactJWE) throws ParseException {
        if (countOccurrences(compactJWE, '.') != 4) {
            throw new ParseException("Invalid number of encoded fields", 0);
        }

        Base64URL[] parts = com.nimbusds.jose.JOSEObject.split(compactJWE);

        boolean allEmpty = stream(parts).allMatch(part -> part.decodeToString().isEmpty());

        if (allEmpty) {
            throw new ParseException("All sections empty", 0);
        }

        return new JWE(parts[0], parts[1], parts[2], parts[3], parts[4]);
    }

    /**
     * Construct a JWE from encoded components
     *
     * @param header       base64 encoded header
     * @param encryptedKey base64 encoded encrypted key
     * @param iv           base64 encoded iv
     * @param ciphertext   base64 encoded ciphertext
     * @param tag          base64 encoded tag
     */
    public static JWE jweFromParts(Base64URL header, Base64URL encryptedKey, Base64URL iv, Base64URL ciphertext, Base64URL tag) {
       return new JWE(header, encryptedKey, iv, ciphertext, tag);
    }
}
