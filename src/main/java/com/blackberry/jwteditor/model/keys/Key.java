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

import com.blackberry.jwteditor.exceptions.UnsupportedKeyException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.JWK;
import org.json.JSONObject;

import java.text.ParseException;

/**
 * Interface containing common elements for all keys
 */
public interface Key {

    String getID();
    String getDescription();
    String toString();

    boolean isPublic();
    boolean isPrivate();
    boolean canSign();
    boolean canVerify();
    boolean canEncrypt();
    boolean canDecrypt();

    boolean hasJWK();

    boolean canConvertToPem();

    JWSAlgorithm[] getSigningAlgorithms();
    JWEAlgorithm[] getKeyEncryptionKeyAlgorithms();

    EncryptionMethod[] getContentEncryptionKeyAlgorithms(JWEAlgorithm keyEncryptionKeyAlgorithm);
    JWSSigner getSigner() throws JOSEException;
    JWSVerifier getVerifier() throws JOSEException;
    JWEEncrypter getEncrypter(JWEAlgorithm kekAlgorithm) throws JOSEException;

    JWEDecrypter getDecrypter(JWEAlgorithm kekAlgorithm) throws JOSEException;

    JSONObject toJSONObject();

    /**
     * Parse a password or JWK from a JSON object
     * @param jsonObject JSON containing the JWK/ serialized password object
     * @return the parsed Key
     * @throws ParseException if parsing fails
     * @throws UnsupportedKeyException if the key construction fails
     */
    static Key fromJSONObject(JSONObject jsonObject) throws ParseException, UnsupportedKeyException {

        if( jsonObject.has("key_id") &&  //NON-NLS
            jsonObject.has("password") && //NON-NLS
            jsonObject.has("salt_length") && //NON-NLS
            jsonObject.has("iterations") //NON-NLS
        ){
            String key_id = (String) jsonObject.get("key_id");  //NON-NLS
            String password = (String) jsonObject.get("password");  //NON-NLS
            Integer salt_length = (Integer) jsonObject.get("salt_length");  //NON-NLS
            Integer iterations = (Integer) jsonObject.get("iterations");  //NON-NLS
            return new PasswordKey(key_id, password, salt_length, iterations);
        }
        else {
            return JWKKeyFactory.from(JWK.parse(jsonObject.toString()));
        }
    }
}
