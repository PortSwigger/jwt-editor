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
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.OctetSequenceKey;

import java.util.Arrays;

class OctetSequenceKeyJWKKey extends AbstractJWKKey {
    private final OctetSequenceKey octetSequenceKey;

    OctetSequenceKeyJWKKey(OctetSequenceKey octetSequenceKey) {
        super(octetSequenceKey, KeyType.OCT);
        this.octetSequenceKey = octetSequenceKey;
    }

    @Override
    public String getDescription() {
        return String.format("%s %d", "OCT", octetSequenceKey.size());
    }

    @Override
    public boolean canSign() {
        return true;
    }

    @Override
    public boolean canVerify() {
        return true;
    }

    @Override
    public boolean canEncrypt() {
        // Can encrypt with all symmetric keys
        return true;
    }

    @Override
    public boolean canConvertToPem() {
        return false;
    }

    @Override
    public JWEEncrypter getEncrypter(JWEAlgorithm kekAlgorithm) throws JOSEException {
        return kekAlgorithm.getName().equals("dir")
                ? new DirectEncrypter(octetSequenceKey)
                : new AESEncrypter(octetSequenceKey);
    }

    @Override
    public JWEDecrypter getDecrypter(JWEAlgorithm kekAlgorithm) throws JOSEException {
        return kekAlgorithm.getName().equals("dir")
                ? new DirectDecrypter(octetSequenceKey)
                : new AESDecrypter(octetSequenceKey);
    }

    @Override
    public JWSSigner getSigner() throws JOSEException {
        byte[] key = padKeyIfNecessary(octetSequenceKey);
        return new MACSigner(key);
    }

    @Override
    public JWSVerifier getVerifier() throws JOSEException {
        byte[] key = padKeyIfNecessary(octetSequenceKey);
        return new MACVerifier(key);
    }

    @Override
    public EncryptionMethod[] getContentEncryptionKeyAlgorithms(JWEAlgorithm keyEncryptionKeyAlgorithm) {
        // dir content encryption requires specific key sizes
        if (keyEncryptionKeyAlgorithm.getName().equals("dir")) { //NON-NLS
            switch (octetSequenceKey.size()) {
                // A128GCM, A192GCM, A256GCM modes require the equivalent size key
                case 128 -> {
                    return new EncryptionMethod[]{EncryptionMethod.A128GCM};
                }
                case 192 -> {
                    return new EncryptionMethod[]{EncryptionMethod.A192GCM};
                }
                // A128CBC_HS256, A192CBC_HS384, A256CBC_HS512 require double the key length as the key is split
                // into two halves, one for AES, the other for HMAC
                case 256 -> {
                    return new EncryptionMethod[]{
                            EncryptionMethod.A256GCM,
                            EncryptionMethod.A128CBC_HS256
                    };
                }
                case 384 -> {
                    return new EncryptionMethod[]{EncryptionMethod.A192CBC_HS384};
                }
                case 512 -> {
                    return new EncryptionMethod[]{EncryptionMethod.A256CBC_HS512};
                }
            }
        }

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
        // OCT key encryption algorithms are dependent on the key size
        return switch (octetSequenceKey.size()) {
            case 128 -> new JWEAlgorithm[]{JWEAlgorithm.DIR, JWEAlgorithm.A128KW, JWEAlgorithm.A128GCMKW};
            case 192 -> new JWEAlgorithm[]{JWEAlgorithm.DIR, JWEAlgorithm.A192KW, JWEAlgorithm.A192GCMKW};
            case 256 -> new JWEAlgorithm[]{JWEAlgorithm.DIR, JWEAlgorithm.A256KW, JWEAlgorithm.A256GCMKW};
            case 384, 512 -> new JWEAlgorithm[]{JWEAlgorithm.DIR};
            default -> new JWEAlgorithm[0];
        };
    }

    @Override
    public JWSAlgorithm[] getSigningAlgorithms() {
        return new JWSAlgorithm[]{
                JWSAlgorithm.HS256,
                JWSAlgorithm.HS384,
                JWSAlgorithm.HS512
        };
    }

    private static byte[] padKeyIfNecessary(OctetSequenceKey octetSequenceKey) {
        byte[] key = octetSequenceKey.toByteArray();

        // Nimbus does not allow keys < 256 bits, so we can just pad them with zeroes to the maximum length of 512 bits
        // due to how HMAC works, padding a key with zeroes does not affect the signature, but allows us to bypass the nimbus check
        return key.length >= 64 ? key : Arrays.copyOf(key, 64);
    }
}
