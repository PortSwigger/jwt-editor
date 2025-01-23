/*
Author : Dolph Flynn

Copyright 2025 Dolph Flynn

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

package com.blackberry.jwteditor.operations.weak;

import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.JWKKeyFactory;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;

class WeakSecretTester {
    private final JWS jws;
    private final JWSHeader verificationInfo;

    public WeakSecretTester(JWS jws) {
        this.jws = jws;

        JWSAlgorithm algorithm = JWSAlgorithm.parse(jws.header().algorithm());
        this.verificationInfo = new JWSHeader.Builder(algorithm).build();
    }

    boolean isSecretCorrect(String secret) throws Exception {
        Base64URL encodedSecret = Base64URL.encode(secret);

        JWK key = new OctetSequenceKey.Builder(encodedSecret).build();
        JWKKey jwkKey = JWKKeyFactory.from(key);

        return jws.verify(jwkKey, verificationInfo);
    }
}
