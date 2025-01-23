/*
Author : Fraser Winterborn

Copyright 2021 BlackBerry Limited

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

import com.blackberry.jwteditor.exceptions.DecryptionException;
import com.blackberry.jwteditor.model.keys.Key;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;
import java.text.ParseException;
import java.util.List;

import static java.util.Collections.emptyList;

/**
 * Class representing a JWE
 */
public class JWE extends JOSEObject {
    private final Base64URL encryptedKey;
    private final Base64URL iv;
    private final Base64URL ciphertext;
    private final Base64URL tag;

    /**
     * Construct a JWE from encoded components
     *
     * @param header       base64 encoded header
     * @param encryptedKey base64 encoded encrypted key
     * @param iv           base64 encoded iv
     * @param ciphertext   base64 encoded ciphertext
     * @param tag          base64 encoded tag
     */
    JWE(Base64URL header, Base64URL encryptedKey, Base64URL iv, Base64URL ciphertext, Base64URL tag) {
        super(header);
        this.encryptedKey = encryptedKey;
        this.iv = iv;
        this.ciphertext = ciphertext;
        this.tag = tag;
    }

    /**
     * Serialize the JWE to compact form
     *
     * @return String containing the JWE in compact serialization
     */
    @Override
    public String serialize() {
        return"%s.%s.%s.%s.%s".formatted(header.toString(), encryptedKey.toString(), iv.toString(), ciphertext.toString(), tag.toString());
    }

    @Override
    public List<Information> information() {
        return emptyList();
    }

    /**
     * Get the encrypted key component as bytes
     *
     * @return the decoded encrypted key
     */
    public byte[] getEncryptedKey() {
        return encryptedKey == null ? new byte[0] : encryptedKey.decode();
    }

    /**
     * Get the ciphertext component as bytes
     *
     * @return the decoded ciphertext
     */
    public byte[] getCiphertext() {
        return ciphertext.decode();
    }

    /**
     * Get the tag component as bytes
     *
     * @return the decoded tag
     */
    public byte[] getTag() {
        return tag.decode();
    }

    /**
     * Get the iv as bytes
     *
     * @return the decoded iv
     */
    public byte[] getIV() {
        return iv.decode();
    }

    /**
     * Decrypt to a JWS using a JWK
     * @param key JWK to decrypt with
     * @return result of the decryption as a JWS
     * @throws DecryptionException if decryption fails
     * @throws ParseException if parsing of plaintext as a JWS fails
     */
    public JWS decrypt(Key key) throws DecryptionException, ParseException {
        // Parse the JWE header to get the decryption algorithms
        JWEHeader header = JWEHeader.parse(this.header.decoded());

        try {
            // Create a new decrypter with the header algs
            JWEDecrypter decrypter = key.getDecrypter(header.getAlgorithm());

            // Try to use the BouncyCastle provider, but fall-back to default if this fails
            Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (provider != null) {
                decrypter.getJCAContext().setProvider(provider);
            }

            // Get the encrypted key component, or null if "dir" encryption
            Base64URL encryptedKey = this.encryptedKey;
            if (header.getAlgorithm().getName().equals("dir")) { //NON-NLS
                encryptedKey = null;
            }

            // Decrypt the ciphertext component using the parsed algorithms and JWK
            byte[] plaintext = decrypter.decrypt(
                    header,
                    encryptedKey,
                    iv,
                    ciphertext,
                    tag
            );

            // Try to parse the result as a JWS and return
            return JWSFactory.parse(new String(plaintext));
        } catch (ParseException e) {
            throw new DecryptionException("JWE contents are not a JWS");
        } catch (Exception e) {
            throw new DecryptionException("Unable to decrypt JWE");
        }
    }
}
