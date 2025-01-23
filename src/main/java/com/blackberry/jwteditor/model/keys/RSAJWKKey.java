/*
Author : Dolph Flynn

Copyright 2023 Dolph Flynn

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

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;

class RSAJWKKey extends AbstractJWKKey {
    private final RSAKey rsaKey;

    RSAJWKKey(RSAKey rsaKey) {
        super(rsaKey, KeyType.RSA);
        this.rsaKey = rsaKey;
    }

    @Override
    public String getDescription() {
        return String.format("RSA %d", rsaKey.size());
    }

    @Override
    public boolean canSign() {
        return rsaKey.isPrivate();
    }

    @Override
    public boolean canVerify() {
        return true;
    }

    @Override
    public boolean canEncrypt() {
        return rsaKey.size() >= 2048;
    }

    @Override
    public boolean canConvertToPem() {
        return true;
    }

    @Override
    public JWEEncrypter getEncrypter(JWEAlgorithm kekAlgorithm) throws JOSEException {
        return new RSAEncrypter(rsaKey.toRSAPublicKey());
    }

    @Override
    public JWEDecrypter getDecrypter(JWEAlgorithm kekAlgorithm) throws JOSEException {
        return new RSADecrypter(rsaKey.toRSAPrivateKey());
    }

    @Override
    public JWSSigner getSigner() throws JOSEException {
        // Allow < 2048-bit keys
        //noinspection deprecation
        return new RSASSASigner(rsaKey.toRSAPrivateKey(), true);
    }

    @Override
    public JWSVerifier getVerifier() throws JOSEException {
        return new RSASSAVerifier(rsaKey.toRSAPublicKey());
    }

    @Override
    public EncryptionMethod[] getContentEncryptionKeyAlgorithms(JWEAlgorithm keyEncryptionKeyAlgorithm) {
        return new EncryptionMethod[]{
                EncryptionMethod.A128GCM,
                EncryptionMethod.A192GCM,
                EncryptionMethod.A256GCM,
                EncryptionMethod.A128CBC_HS256,
                EncryptionMethod.A192CBC_HS384,
                EncryptionMethod.A256CBC_HS512,
        };
    }

    @Override
    public JWEAlgorithm[] getKeyEncryptionKeyAlgorithms() {
        //noinspection deprecation
        return new JWEAlgorithm[]{JWEAlgorithm.RSA1_5, JWEAlgorithm.RSA_OAEP, JWEAlgorithm.RSA_OAEP_256};
    }

    @Override
    public JWSAlgorithm[] getSigningAlgorithms() {
        return switch (rsaKey.size()) {
            case 512 -> new JWSAlgorithm[]{
                    JWSAlgorithm.RS256
            };

            case 1024 -> new JWSAlgorithm[]{
                    JWSAlgorithm.RS256,
                    JWSAlgorithm.RS384,
                    JWSAlgorithm.RS512,
                    JWSAlgorithm.PS256,
                    JWSAlgorithm.PS384
            };

            default -> new JWSAlgorithm[]{
                    JWSAlgorithm.RS256,
                    JWSAlgorithm.RS384,
                    JWSAlgorithm.RS512,
                    JWSAlgorithm.PS256,
                    JWSAlgorithm.PS384,
                    JWSAlgorithm.PS512
            };
        };
    }
}
