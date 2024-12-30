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

package com.blackberry.jwteditor;

import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.jose.JWSFactory;
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.JWKKeyFactory;
import com.blackberry.jwteditor.model.keys.PasswordKey;
import com.blackberry.jwteditor.utils.PEMUtils;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import utils.BouncyCastleExtension;

import java.util.List;
import java.util.stream.Stream;

import static com.blackberry.jwteditor.KeyUtils.*;
import static com.blackberry.jwteditor.model.jose.JWSFactory.jwsFromParts;
import static com.nimbusds.jose.JWSAlgorithm.*;
import static data.PemData.*;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

@ExtendWith(BouncyCastleExtension.class)
class KeySigningTests {
    private static final JWS TEST_JWS = jwsFromParts(
            Base64URL.encode("{\"typ\":\"JWT\",\"alg\":\"HS256\"}"),
            Base64URL.encode("{\"sub\":\"Test\"}"),
            Base64URL.encode(new byte[0])
    );

    private static Stream<Arguments> keysAndExpectedSigningAlgorithms() throws Exception {
        return Stream.of(
                // RSA
                arguments(rsaKeyFrom(RSA512Private), List.of(RS256)),
                arguments(rsaKeyFrom(RSA1024Private), List.of(RS256, RS384, RS512, PS256, PS384)),
                arguments(rsaKeyFrom(RSA2048Private), List.of(RS256, RS384, RS512, PS256, PS384, PS512)),
                arguments(rsaKeyFrom(RSA3072Private), List.of(RS256, RS384, RS512, PS256, PS384, PS512)),
                arguments(rsaKeyFrom(RSA4096Private), List.of(RS256, RS384, RS512, PS256, PS384, PS512)),
                // EC
                arguments(ecKeyFrom(PRIME256v1PrivateSEC1), List.of(ES256)),
                arguments(ecKeyFrom(PRIME256v1PrivatePKCS8), List.of(ES256)),
                arguments(ecKeyFrom(SECP256K1PrivateSEC1), List.of(ES256K)),
                arguments(ecKeyFrom(SECP256K1PrivatePKCS8), List.of(ES256K)),
                arguments(ecKeyFrom(SECP384R1PrivateSEC1), List.of(ES384)),
                arguments(ecKeyFrom(SECP384R1PrivatePKCS8), List.of(ES384)),
                arguments(ecKeyFrom(SECP521R1PrivateSEC1), List.of(ES512)),
                arguments(ecKeyFrom(SECP521R1PrivatePCKS8), List.of(ES512)),
                // OKP
                arguments(okpPrivateKeyFrom(ED448Private), List.of(EdDSA)),
                arguments(okpPrivateKeyFrom(ED25519Private), List.of(EdDSA)),
                arguments(okpPrivateKeyFrom(X448Private), emptyList()),
                arguments(okpPrivateKeyFrom(X25519Private), emptyList()),
                // Octet Sequences
                arguments(JWKKeyFactory.from(new OctetSequenceKeyGenerator(128).generate()), List.of(HS256, HS384, HS512)),
                arguments(JWKKeyFactory.from(new OctetSequenceKeyGenerator(192).generate()), List.of(HS256, HS384, HS512)),
                arguments(JWKKeyFactory.from(new OctetSequenceKeyGenerator(256).generate()), List.of(HS256, HS384, HS512)),
                arguments(JWKKeyFactory.from(new OctetSequenceKeyGenerator(384).generate()), List.of(HS256, HS384, HS512)),
                arguments(JWKKeyFactory.from(new OctetSequenceKeyGenerator(512).generate()), List.of(HS256, HS384, HS512)),
                arguments(JWKKeyFactory.from(new OctetSequenceKey.Builder("secret123".getBytes()).build()), List.of(HS256, HS384, HS512))
        );
    }

    @ParameterizedTest
    @MethodSource("keysAndExpectedSigningAlgorithms")
    void keysCanSigning(JWKKey key, List<JWSAlgorithm> expectedAlgorithms) {
        assertThat(key.canSign()).isEqualTo(!expectedAlgorithms.isEmpty());
    }

    @ParameterizedTest
    @MethodSource("keysAndExpectedSigningAlgorithms")
    void keysHaveCorrectSigningAlgorithms(JWKKey key, List<JWSAlgorithm> expectedAlgorithms) {
        assertThat(key.getSigningAlgorithms()).containsExactlyElementsOf(expectedAlgorithms);
    }

    @ParameterizedTest
    @MethodSource("com.blackberry.jwteditor.KeyUtils#keySigningAlgorithmPairs")
    void keysCanSignCorrectly(JWKKey key, JWSAlgorithm algorithm) throws Exception {
        JWSHeader signingInfo = new JWSHeader.Builder(algorithm).build();

        Base64URL header = signingInfo.toBase64URL();
        Base64URL payload = TEST_JWS.claims().encoded();

        JWS jws = JWSFactory.sign(key, header, payload, signingInfo);

        assertThat(jws.verify(key, signingInfo)).isTrue();
    }

    @Test
    void givenEmptyOctetSequenceKey_whenSigningWithHs256_thenCanGenerateAndVerifySignature() throws Exception {
        JWK jwk = OctetSequenceKey.parse("{\"kty\": \"oct\",\"k\": \"\"}");
        JWKKey key = JWKKeyFactory.from(jwk);
        JWSHeader signingInfo = new JWSHeader.Builder(HS256).build();

        Base64URL header = signingInfo.toBase64URL();
        Base64URL payload = TEST_JWS.claims().encoded();

        JWS jws = JWSFactory.sign(key, header, payload, signingInfo);

        assertThat(jws.verify(key, signingInfo)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {ED448Private, ED25519Private})
    void okpSigning(String pem) throws Exception {
        JWK octetKeyPair = PEMUtils.pemToOctetKeyPair(pem);
        JWKKey privateKey = JWKKeyFactory.from(octetKeyPair);
        JWKKey publicKey = JWKKeyFactory.from(octetKeyPair.toPublicJWK());

        JWSHeader signingInfo = new JWSHeader.Builder(EdDSA).build();
        Base64URL header = signingInfo.toBase64URL();
        Base64URL payload = TEST_JWS.claims().encoded();

        JWS jws = JWSFactory.sign(privateKey, header, payload, signingInfo);

        assertThat(jws.verify(publicKey, signingInfo)).isTrue();
    }

    @Test
    void passwordSigning() {
        PasswordKey key = new PasswordKey("Test", "Test", 8, 1000);

        assertThat(key.canSign()).isFalse();
        assertThat(key.canVerify()).isFalse();
    }
}
