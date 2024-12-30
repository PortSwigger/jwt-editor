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

package com.blackberry.jwteditor;

import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.jose.JWSFactory;
import com.blackberry.jwteditor.model.jose.JWSFactory.SigningUpdateMode;
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.JWKKeyFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.stream.Stream;

import static com.blackberry.jwteditor.model.jose.JWSFactory.SigningUpdateMode.*;
import static com.blackberry.jwteditor.model.jose.JWSFactory.jwsFromParts;
import static com.blackberry.jwteditor.utils.PEMUtils.pemToRSAKey;
import static com.nimbusds.jose.HeaderParameterNames.KEY_ID;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static data.PemData.RSA512Private;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class SigningTests {
    private static final String UPDATED_KID = "1ba163b6-2f3b-432f-9f4f-97365be3ead5";
    private static final JWS TEST_JWS = jwsFromParts(
            Base64URL.encode("{\"typ\":\"JWT\",\"alg\":\"HS256\"}"),
            Base64URL.encode("{\"sub\":\"Test\"}"),
            Base64URL.from("kbHMdDtPhNRW2D4BzRIiRTu1LRhTFpdQRvWzXS_tud0")
    );

    private static Stream<Arguments> data() {
        return Stream.of(
            arguments(DO_NOT_MODIFY_HEADER, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJUZXN0In0.C81lV9D-_pQzSdOL9cfgcIFluKc5tsUQh8Wi7AuWLIFc25nTL3_OAz8-Ts3XHMS03pBFZeuCAecYtycI8MVekA"),
            arguments(UPDATE_ALGORITHM_ONLY, "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJUZXN0In0.n5LiQOVnYyFgQA6faanqV1m1rZh8ToJ8SyL59x1h5kd-TkeYaU9KzoIDqVKOglvLxZ4TMmIQ7DYDrfzLIdt5IA"),
            arguments(UPDATE_ALGORITHM_TYPE_AND_KID, "eyJraWQiOiIxYmExNjNiNi0yZjNiLTQzMmYtOWY0Zi05NzM2NWJlM2VhZDUiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJUZXN0In0.eyMutQ_Jr_o_qxvWnbElYRqnfi_jVN13OliKtbGAYmI6MX7WrYbwmSW70JEpv9YIhGOYo4KkqcM3psUeEwwRpA")
        );
    }

    @ParameterizedTest
    @MethodSource("data")
    void givenJWS_whenSignedWithName_thenNewJWSCorrect(SigningUpdateMode mode, String expectedJWS) throws Exception {
        Map<String, Object> json = pemToRSAKey(RSA512Private).toJSONObject();
        json.put(KEY_ID, UPDATED_KID);
        JWKKey jwkKey = JWKKeyFactory.from(JWK.parse(json));

        JWS updatedJWS = JWSFactory.sign(
                jwkKey,
                RS256,
                mode,
                TEST_JWS
        );

        assertThat(updatedJWS.serialize()).isEqualTo(expectedJWS);
    }
}
