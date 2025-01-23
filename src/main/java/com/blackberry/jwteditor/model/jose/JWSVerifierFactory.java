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

import com.blackberry.jwteditor.exceptions.VerificationException;
import com.blackberry.jwteditor.model.keys.Key;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;

import java.security.Provider;
import java.security.Security;
import java.util.Set;

import static com.nimbusds.jose.JWSAlgorithm.ES256K;
import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

class JWSVerifierFactory {
    static final Set<Algorithm> BOUNCY_CASTLE_ONLY_ALGORITHMS = Set.of(
            ES256K
    );

    static JWSVerifier verifierFor(Key key, JWSAlgorithm algorithm) throws VerificationException {
        JWSVerifier verifier;

        try {
            verifier = key.getVerifier();
        } catch (JOSEException e) {
            throw new VerificationException(e.getMessage());
        }

        if (BOUNCY_CASTLE_ONLY_ALGORITHMS.contains(algorithm)) {
            try {
                Provider provider = Security.getProvider(PROVIDER_NAME);

                if (provider != null) {
                    verifier.getJCAContext().setProvider(provider);
                }
            } catch (Throwable t) {
                throw new VerificationException("Unable to load the BouncyCastle.", t);
            }
        }

        return verifier;
    }
}
