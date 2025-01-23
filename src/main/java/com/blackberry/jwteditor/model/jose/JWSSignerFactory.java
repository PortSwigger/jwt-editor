/*
Author : Dolph Flynn

Copyright 2024 Dolph Flynn

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

import com.blackberry.jwteditor.exceptions.SigningException;
import com.blackberry.jwteditor.model.keys.Key;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;

import java.security.Provider;
import java.security.Security;

import static com.blackberry.jwteditor.model.jose.JWSVerifierFactory.BOUNCY_CASTLE_ONLY_ALGORITHMS;
import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

class JWSSignerFactory {

    static JWSSigner signerFor(Key key, JWSAlgorithm algorithm) throws SigningException {
        com.nimbusds.jose.JWSSigner signer;

        try {
            signer = key.getSigner();
        } catch (JOSEException e) {
            throw new SigningException(e.getMessage());
        }

        if (BOUNCY_CASTLE_ONLY_ALGORITHMS.contains(algorithm)) {
            try {
                Provider provider = Security.getProvider(PROVIDER_NAME);

                if (provider != null) {
                    signer.getJCAContext().setProvider(provider);
                }
            } catch (Throwable t) {
                throw new SigningException("Unable to load the BouncyCastle.", t);
            }
        }

        return new JWSSigner(signer);
    }
}
