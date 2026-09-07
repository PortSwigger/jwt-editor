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

import com.blackberry.jwteditor.exceptions.PemException;
import com.blackberry.jwteditor.exceptions.UnsupportedKeyException;
import com.blackberry.jwteditor.model.keys.JWKKeyFactory;
import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.model.keys.PasswordKey;
import com.blackberry.jwteditor.pem.PemKeyFactory;
import com.nimbusds.jose.jwk.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.text.ParseException;
import java.util.Arrays;
import java.util.stream.Stream;

import static com.blackberry.jwteditor.JWKData.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class JWKToPEMTests {
    private static Stream<String> ecPrivateValidJWKs() {
        return Stream.of(ECPrivate);
    }

    @ParameterizedTest
    @MethodSource("ecPrivateValidJWKs")
    void ecPrivateKeyToPemValid(String jwkString) throws PemException, ParseException {
        ECKey ecKey = ECKey.parse(jwkString);
        assertThat(ecKey.isPrivate()).isTrue();

        String pem = PemKeyFactory.jwkToPemKey((JWK) ecKey).toString();
        assertThat(pem).isNotEmpty();
    }

    private static Stream<String> ecPublicValidJWKs() {
        return Stream.of(ECPublic);
    }

    @ParameterizedTest
    @MethodSource("ecPublicValidJWKs")
    void ecPublicKeyToPemValid(String jwkString) throws PemException, ParseException {
        ECKey ecKey = ECKey.parse(jwkString);
        assertThat(ecKey.isPrivate()).isFalse();

        String pem = PemKeyFactory.jwkToPemKey((JWK) ecKey).toString();
        assertThat(pem).isNotEmpty();
    }

    private static Stream<String> ecInvalidJWKs() {
        return Stream.of(RSAPublic, RSAPrivate, OKPPrivate, OKPPublic).flatMap(Arrays::stream);
    }

    @ParameterizedTest
    @MethodSource("ecInvalidJWKs")
    void ecKeyToPemInvalid(String jwkString) {
        assertThrows(Exception.class, () -> ECKey.parse(jwkString));
    }

    static Stream<String> rsaPrivateValidJWKs() {
        return Stream.of(RSAPrivate);
    }

    @ParameterizedTest
    @MethodSource("rsaPrivateValidJWKs")
    void rsaPrivateKeyToPemValid(String jwkString) throws PemException, ParseException {
        RSAKey rsaKey = RSAKey.parse(jwkString);
        assertThat(rsaKey.isPrivate()).isTrue();

        String pem = PemKeyFactory.jwkToPemKey((JWK) rsaKey).toString();
        assertThat(pem).isNotEmpty();
    }

    static Stream<String> rsaPublicValidJWKs() {
        return Stream.of(RSAPublic);
    }

    @ParameterizedTest
    @MethodSource("rsaPublicValidJWKs")
    void rsaPublicKeyToPemValid(String jwkString) throws PemException, ParseException {
        RSAKey rsaKey = RSAKey.parse(jwkString);
        assertThat(rsaKey.isPrivate()).isFalse();

        String pem = PemKeyFactory.jwkToPemKey((JWK) rsaKey).toString();
        assertThat(pem).isNotEmpty();
    }

    private static Stream<String> rsaInvalidJWKs() {
        return Stream.of(ECPrivate, ECPublic, OKPPrivate, OKPPublic).flatMap(Arrays::stream);
    }

    @ParameterizedTest
    @MethodSource("rsaInvalidJWKs")
    void rsaKeyToPemInvalid(String jwkString) {
        assertThrows(Exception.class, () -> RSAKey.parse(jwkString));
    }

    private static Stream<String> ocpPrivateValidJWKs() {
        return Stream.of(OKPPrivate);
    }

    @ParameterizedTest
    @MethodSource("ocpPrivateValidJWKs")
    void octetKeyPairPrivateToPemValid(String jwkString) throws PemException, ParseException {
        OctetKeyPair octetKeyPair = OctetKeyPair.parse(jwkString);
        assertThat(octetKeyPair.isPrivate()).isTrue();

        String pem = PemKeyFactory.jwkToPemKey((JWK) octetKeyPair).toString();
        assertThat(pem).isNotEmpty();
    }

    private static Stream<String> ocpPublicValidJWKs() {
        return Stream.of(OKPPublic);
    }

    @ParameterizedTest
    @MethodSource("ocpPublicValidJWKs")
    void octetKeyPairPublicToPemValid(String jwkString) throws PemException, ParseException {
        OctetKeyPair octetKeyPair = OctetKeyPair.parse(jwkString);
        assertThat(octetKeyPair.isPrivate()).isFalse();

        String pem = PemKeyFactory.jwkToPemKey((JWK) octetKeyPair).toString();
        assertThat(pem).isNotEmpty();
    }

    private static Stream<String> ocpInvalidJWKs() {
        return Stream.of(ECPrivate, ECPublic, RSAPrivate, RSAPublic).flatMap(Arrays::stream);
    }

    @ParameterizedTest
    @MethodSource("ocpInvalidJWKs")
    void octetKeyPairToPemInvalid(String jwkString) {
        assertThrows(Exception.class, () -> OctetKeyPair.parse(jwkString));
    }

    private static Stream<Arguments> keyToPemData() throws ParseException, UnsupportedKeyException {
        return Stream.of(
                arguments(JWKKeyFactory.from(RSAKey.parse(RSA2048PrivateDEN)), true),
                arguments(JWKKeyFactory.from(ECKey.parse(P256Private)), true),
                arguments(JWKKeyFactory.from(OctetKeyPair.parse(Ed25519Private)), true),
                arguments(JWKKeyFactory.from(new OctetSequenceKey.Builder("secret123".getBytes()).build()), false),
                arguments(new PasswordKey("keyId", "secret123", 17, 29), false)
        );
    }

    @ParameterizedTest
    @MethodSource("keyToPemData")
    void testCanConvertToPemForJWKs(Key key, boolean canConvert) {
        assertThat(key.canConvertToPem()).isEqualTo(canConvert);
    }
}
