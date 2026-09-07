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
import com.blackberry.jwteditor.pem.PemKeyFactory;
import com.blackberry.jwteditor.utils.PEMUtils;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import utils.BouncyCastleExtension;

import java.util.Arrays;
import java.util.stream.Stream;

import static data.PemData.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(BouncyCastleExtension.class)
class PEMToJWKTests {
    private static Stream<String> ecPrivateValidPEMs() {
        return Stream.of(ECPrivate);
    }

    @ParameterizedTest
    @MethodSource("ecPrivateValidPEMs")
    void pemToECKeyPrivateValid(String pem) throws PemException {
        JWK jwk = PEMUtils.pemToECKey(pem);
        assertThat(jwk).isInstanceOf(ECKey.class);
        assertThat(jwk.isPrivate()).isTrue();
    }

    private static Stream<String> ecPublicValidPEMs() {
        return Stream.of(ECPublic);
    }

    @ParameterizedTest
    @MethodSource("ecPublicValidPEMs")
    void pemToECKeyPublicValid(String pem) throws PemException {
        JWK jwk = PEMUtils.pemToECKey(pem);
        assertThat(jwk).isInstanceOf(ECKey.class);
        assertThat(jwk.isPrivate()).isFalse();
    }

    private static Stream<String> ecInvalidPEMs() {
        return Stream.of(RSAPublic, RSAPrivate, OKPPrivate, OKPPublic).flatMap(Arrays::stream);
    }

    @ParameterizedTest
    @MethodSource("ecInvalidPEMs")
    void pemToECKeyPairInvalid(String pem) {
        assertThrows(PemException.class, () -> PEMUtils.pemToECKey(pem));
    }

    static Stream<String> rsaPrivateValidPEMs() {
        return Stream.of(RSAPrivate);
    }

    @ParameterizedTest
    @MethodSource("rsaPrivateValidPEMs")
    void pemToRSAKeyPrivateValid(String pem) throws PemException {
        JWK jwk = PEMUtils.pemToRSAKey(pem);
        assertThat(jwk).isInstanceOf(RSAKey.class);
        assertThat(jwk.isPrivate()).isTrue();
    }

    static Stream<String> rsaPublicValidPEMs() {
        return Stream.of(RSAPublic);
    }

    @ParameterizedTest
    @MethodSource("rsaPublicValidPEMs")
    void pemToRSAKeyPairPublicValid(String pem) throws PemException {
        JWK jwk = PEMUtils.pemToRSAKey(pem);
        assertThat(jwk).isInstanceOf(RSAKey.class);
        assertThat(jwk.isPrivate()).isFalse();
    }

    private static Stream<String> rsaInvalidPEMs() {
        return Stream.of(ECPublic, ECPrivate, OKPPrivate, OKPPublic).flatMap(Arrays::stream);
    }

    @ParameterizedTest
    @MethodSource("rsaInvalidPEMs")
    void pemToRSAKeyPairInvalid(String pem) {
        assertThrows(PemException.class, () -> PEMUtils.pemToRSAKey(pem));
    }

    private static Stream<String> ocpPrivateValidPEMs() {
        return Stream.of(OKPPrivate);
    }

    @ParameterizedTest
    @MethodSource("ocpPrivateValidPEMs")
    void pemToOctetKeyPairPrivateValid(String pem) throws PemException {
        JWK jwk = PEMUtils.pemToOctetKeyPair(pem);

        assertThat(jwk).isInstanceOf(OctetKeyPair.class);
        OctetKeyPair octetKeyPair = (OctetKeyPair) jwk;
        assertThat(octetKeyPair.getX()).isNotNull();
        assertThat(octetKeyPair.isPrivate()).isTrue();
        assertThat(octetKeyPair.getD()).isNotNull();
    }

    private static Stream<String> ocpPublicValidPEMs() {
        return Stream.of(OKPPublic);
    }

    @ParameterizedTest
    @MethodSource("ocpPublicValidPEMs")
    void pemToOctetKeyPairPublicValid(String pem) throws PemException {
        JWK jwk = PEMUtils.pemToOctetKeyPair(pem);

        assertThat(jwk).isInstanceOf(OctetKeyPair.class);
        OctetKeyPair octetKeyPair = (OctetKeyPair) jwk;
        assertThat(octetKeyPair.getX()).isNotNull();
        assertThat(octetKeyPair.isPrivate()).isFalse();
        assertThat(octetKeyPair.getD()).isNull();
    }

    private static Stream<String> ocpInvalidPEMs() {
        return Stream.of(ECPublic, ECPrivate, RSAPrivate, RSAPublic).flatMap(Arrays::stream);
    }

    @ParameterizedTest
    @MethodSource("ocpInvalidPEMs")
    void pemToOctetKeyPairInvalid(String pem) {
        assertThrows(PemException.class, () -> PEMUtils.pemToOctetKeyPair(pem));
    }

    private static Stream<String> ocpValidPEMs() {
        return Stream.of(OKPPrivate, OKPPublic).flatMap(Arrays::stream);
    }

    @ParameterizedTest
    @MethodSource("ocpValidPEMs")
    void octetKeyPairPemRoundTrip(String pem) throws PemException {
        JWK jwk = PEMUtils.pemToOctetKeyPair(pem);

        assertThat(jwk).isInstanceOf(OctetKeyPair.class);
        OctetKeyPair octetKeyPair = (OctetKeyPair) jwk;
        String newPem = PemKeyFactory.jwkToPemKey(octetKeyPair).toString();
        assertThat(pem).isEqualTo(newPem);
    }
}