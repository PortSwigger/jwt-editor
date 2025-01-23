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

package com.blackberry.jwteditor.model.keys;

import com.blackberry.jwteditor.utils.Utils;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.PasswordBasedDecrypter;
import com.nimbusds.jose.crypto.PasswordBasedEncrypter;
import org.json.JSONObject;

/**
 * Class for password-based secrets
 */
public class PasswordKey implements Key {

    private final int iterations;
    private final String password;
    private final int saltLength;
    private final String keyId;

    /**
     * Construct a Key from password parameters
     *
     * @param keyId the key ID to use
     * @param password the password
     * @param saltLength the length of the salt to generate for the key derivation function
     * @param iterations the number of iterations to use for the key derivation function
     */
    public PasswordKey(String keyId, String password, int saltLength, int iterations){
        this.keyId = keyId;
        this.password = password;
        this.saltLength = saltLength;
        this.iterations = iterations;
    }

    /**
     * Get the key identifier
     * @return JWK 'kid' value
     */
    @Override
    public String getID() {
        return keyId;
    }

    /**
     * Get a String description of the key
     *
     * @return the key description
     */
    @Override
    public String getDescription() {
        return String.format("%s (%s)", Utils.getResourceString("password"), password); //NON-NLS
    }

    /**
     * Is the key a public key
     *
     * @return always false for passwords
     */
    @Override
    public boolean isPublic() {
        return false;
    }

    /**
     * Is the key a private key
     *
     * @return always true for passwords
     */
    @Override
    public boolean isPrivate() {
        return true;
    }

    /**
     * Is the key able to sign a payload
     *
     * @return always false for passwords
     */
    @Override
    public boolean canSign() {
        return false;
    }

    /**
     * Is the key able to verify a payload
     *
     * @return always false for passwords
     */
    @Override
    public boolean canVerify() {
        return false;
    }

    /**
     * Is the key able to encrypt a payload
     *
     * @return always true for passwords
     */
    @Override
    public boolean canEncrypt() {
        return true;
    }

    /**
     * Is the key able to decrypt a payload
     *
     * @return always true for passwords
     */
    @Override
    public boolean canDecrypt() {
        return true;
    }

    /**
     * Does the key have a JWK representation
     *
     * @return always false for passwords
     */
    @Override
    public boolean hasJWK() {
        return false;
    }

    @Override
    public boolean canConvertToPem() {
        return false;
    }

    /**
     * Get the signing algorithms that can be used with this key
     *
     * @return array of allowed signing algorithms
     */
    @Override
    public JWSAlgorithm[] getSigningAlgorithms() {
        return new JWSAlgorithm[]{};
    }

    /**
     * Get the key encryption algorithms that can be used with this key
     *
     * @return array of allowed key encryption algorithms
     */
    @Override
    public JWEAlgorithm[] getKeyEncryptionKeyAlgorithms() {
        return new JWEAlgorithm[]{
                JWEAlgorithm.PBES2_HS256_A128KW,
                JWEAlgorithm.PBES2_HS384_A192KW,
                JWEAlgorithm.PBES2_HS512_A256KW
        };
    }

    /**
     * Get the content encryption algorithms that can be used with this key
     *
     * @return array of allowed key encryption algorithms
     */
    @Override
    public EncryptionMethod[] getContentEncryptionKeyAlgorithms(JWEAlgorithm keyEncryptionKeyAlgorithm) {
        return new EncryptionMethod[]{
                EncryptionMethod.A128GCM,
                EncryptionMethod.A192GCM,
                EncryptionMethod.A256GCM,
                EncryptionMethod.A128CBC_HS256,
                EncryptionMethod.A128CBC_HS256_DEPRECATED,
                EncryptionMethod.A192CBC_HS384,
                EncryptionMethod.A256CBC_HS512,
                EncryptionMethod.A256CBC_HS512_DEPRECATED,
        };
    }

    /**
     * Get the appropriate signer for the key type
     *
     * @return the nimbus-jose JWSSigner to perform the signing operation
     */
    @Override
    public JWSSigner getSigner() {
        throw new IllegalStateException("Unreachable - Passwords cannot be used to sign");
    }

    /**
     * Get the appropriate verifier for the key type
     *
     * @return the nimbus-jose JWSVerifier to perform the verification operation
     */
    @Override
    public JWSVerifier getVerifier() {
        throw new IllegalStateException("Unreachable - Passwords cannot be used to verify");
    }

    /**
     * Get the appropriate encrypter for the key type
     *
     * @return the nimbus-jose JWEEncrypter to perform the encryption operation
     */
    @Override
    public JWEEncrypter getEncrypter(JWEAlgorithm kekAlgorithm) {
        return new PasswordBasedEncrypter(password, saltLength, iterations);
    }

    /**
     * Get the appropriate decrypter for the key type
     *
     * @return the nimbus-jose JWEDecrypter to perform the decryption operation
     */
    @Override
    public JWEDecrypter getDecrypter(JWEAlgorithm kekAlgorithm) {
        return new PasswordBasedDecrypter(password);
    }

    /**
     * Get the key as a JSON object
     * @return a JSONObject representing the key
     */
    @Override
    public JSONObject toJSONObject() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("key_id", keyId); //NON-NLS
        jsonObject.put("password", password); //NON-NLS
        jsonObject.put("salt_length", saltLength); //NON-NLS
        jsonObject.put("iterations", iterations); //NON-NLS
        return jsonObject;
    }

    /**
     * Get a string representation of the key
     * @return a String representing the key
     */
    @Override
    public String toString() {
        return String.format("%s (%s - %s)", keyId, Utils.getResourceString("password"), password); //NON-NLS
    }

    /**
     * Get the password
     *
     * @return the password
     */
    public String getPassword() {
        return password;
    }

    /**
     * Get the salt length
     *
     * @return salt length
     */
    public int getSaltLength() {
        return saltLength;
    }

    /**
     * Get the number of KDF interations
     * @return number of iterations
     */
    public int getIterations() {
        return iterations;
    }
}
