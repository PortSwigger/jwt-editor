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
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;

class ECJWKKey extends AbstractJWKKey {
    private final ECKey ecKey;

    ECJWKKey(ECKey ecKey) {
        super(ecKey, KeyType.EC);
        this.ecKey = ecKey;
    }

    @Override
    public String getDescription() {
        return ecKey.getCurve().getName();
    }

    @Override
    public boolean canSign() {
        return ecKey.isPrivate();
    }

    @Override
    public boolean canVerify() {
        return true;
    }

    @Override
    public boolean canEncrypt() {
        // Can encrypt with all EC curves other than secp256k1
        return !ecKey.getCurve().getStdName().equals("secp256k1");
    }

    @Override
    public boolean canConvertToPem() {
        return true;
    }

    @Override
    public JWEEncrypter getEncrypter(JWEAlgorithm kekAlgorithm) throws JOSEException {
        return new ECDHEncrypter(ecKey.toECPublicKey());
    }

    @Override
    public JWEDecrypter getDecrypter(JWEAlgorithm kekAlgorithm) throws JOSEException {
        return new ECDHDecrypter(ecKey.toECPrivateKey());
    }

    @Override
    public JWSSigner getSigner() throws JOSEException {
        return new ECDSASigner(ecKey.toECPrivateKey());
    }

    @Override
    public JWSVerifier getVerifier() throws JOSEException {
        return new ECDSAVerifier(ecKey.toECPublicKey());
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
        return new JWEAlgorithm[]{JWEAlgorithm.ECDH_ES, JWEAlgorithm.ECDH_ES_A128KW, JWEAlgorithm.ECDH_ES_A192KW, JWEAlgorithm.ECDH_ES_A256KW};
    }

    @Override
    public JWSAlgorithm[] getSigningAlgorithms() {
        return switch (ecKey.getCurve().getName()) {
            case "P-256" -> new JWSAlgorithm[]{JWSAlgorithm.ES256};
            case "secp256k1" -> new JWSAlgorithm[]{JWSAlgorithm.ES256K};
            case "P-384" -> new JWSAlgorithm[]{JWSAlgorithm.ES384};
            case "P-521" -> new JWSAlgorithm[]{JWSAlgorithm.ES512};
            default -> new JWSAlgorithm[0];
        };
    }
}
