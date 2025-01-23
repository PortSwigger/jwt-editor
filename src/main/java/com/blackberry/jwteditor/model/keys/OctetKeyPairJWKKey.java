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

import com.blackberry.jwteditor.cryptography.okp.OKPDecrypter;
import com.blackberry.jwteditor.cryptography.okp.OKPEncrypter;
import com.blackberry.jwteditor.cryptography.okp.OKPSigner;
import com.blackberry.jwteditor.cryptography.okp.OKPVerifier;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.OctetKeyPair;

class OctetKeyPairJWKKey extends AbstractJWKKey {
    private final OctetKeyPair octetKeyPair;

    OctetKeyPairJWKKey(OctetKeyPair octetKeyPair) {
        super(octetKeyPair, KeyType.OKP);
        this.octetKeyPair = octetKeyPair;
    }

    @Override
    public String getDescription() {
        return octetKeyPair.getCurve().getName();
    }

    @Override
    public boolean canSign() {
        // Signing with OKP requires an Edwards Curve private key
        return switch (octetKeyPair.getCurve().getStdName()) {
            case "Ed25519", "Ed448" -> octetKeyPair.isPrivate();
            default -> false;
        };
    }

    @Override
    public boolean canVerify() {
        // Verification with OKP requires an Edwards Curve key
        return switch (octetKeyPair.getCurve().getStdName()) {
            case "Ed25519", "Ed448" -> true;
            default -> false;
        };
    }

    @Override
    public boolean canEncrypt() {
        // X25519/X448 required for OKP encryption
        return switch (octetKeyPair.getCurve().getStdName()) {
            case "X25519", "X448" -> true;
            default -> false;
        };
    }

    @Override
    public boolean canConvertToPem() {
        return true;
    }

    @Override
    public JWEEncrypter getEncrypter(JWEAlgorithm kekAlgorithm) throws JOSEException {
        return new OKPEncrypter(octetKeyPair.toPublicJWK());
    }

    @Override
    public JWEDecrypter getDecrypter(JWEAlgorithm kekAlgorithm) throws JOSEException {
        return new OKPDecrypter(octetKeyPair);
    }

    @Override
    public JWSSigner getSigner() throws JOSEException {
        return new OKPSigner(octetKeyPair);
    }

    @Override
    public JWSVerifier getVerifier() throws JOSEException {
        return new OKPVerifier(octetKeyPair.toPublicJWK());
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
        return new JWEAlgorithm[]{JWEAlgorithm.ECDH_ES};
    }

    @Override
    public JWSAlgorithm[] getSigningAlgorithms() {
        return switch (octetKeyPair.getCurve().getStdName()) {
            case "Ed25519", "Ed448" -> new JWSAlgorithm[]{JWSAlgorithm.EdDSA};
            default -> new JWSAlgorithm[0];
        };
    }
}
