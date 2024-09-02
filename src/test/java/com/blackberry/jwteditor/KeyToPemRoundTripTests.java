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
import com.blackberry.jwteditor.utils.PEMUtils;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import utils.BouncyCastleExtension;

import java.text.ParseException;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(BouncyCastleExtension.class)
class KeyToPemRoundTripTests {
    private static final String KID_REGEX = "\"kid\":\"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\",";

    @ParameterizedTest
    @MethodSource("com.blackberry.jwteditor.PEMToJWKTests#rsaPrivateValidPEMs")
    void privateRsaPEMtoJWK(String pem) throws PemException {
        JWK rsaKey = PEMUtils.pemToRSAKey(pem);
        String newPem = PEMUtils.jwkToPem(rsaKey);
        assertThat(pem).isEqualTo(newPem);
    }

    @ParameterizedTest
    @MethodSource("com.blackberry.jwteditor.PEMToJWKTests#rsaPublicValidPEMs")
    void publicRsaPEMtoJWK(String pem) throws PemException {
        JWK rsaKey = PEMUtils.pemToRSAKey(pem);
        String newPem = PEMUtils.jwkToPem(rsaKey);
        assertThat(pem).isEqualTo(newPem);
    }

    @ParameterizedTest
    @MethodSource("com.blackberry.jwteditor.JWKToPEMTests#rsaPrivateValidJWKs")
    void privateRsaJWKtoPEM(String jwkString) throws PemException, ParseException {
        RSAKey rsaKey = RSAKey.parse(jwkString);
        String pem = PEMUtils.jwkToPem(rsaKey);

        JWK jwk = PEMUtils.pemToRSAKey(pem);
        assertEqualsIgnoringWhitespaceAndKid(jwk.toJSONString(), jwkString);
    }

    @ParameterizedTest
    @MethodSource("com.blackberry.jwteditor.JWKToPEMTests#rsaPublicValidJWKs")
    void publicRsaJWKtoPEM(String jwkString) throws PemException, ParseException {
        RSAKey rsaKey = RSAKey.parse(jwkString);
        String pem = PEMUtils.jwkToPem(rsaKey);

        JWK jwk = PEMUtils.pemToRSAKey(pem);
        assertEqualsIgnoringWhitespaceAndKid(jwk.toJSONString(), jwkString);
    }

    @ParameterizedTest
    @MethodSource("com.blackberry.jwteditor.PEMToJWKTests#ecPrivateValidPEMs")
    void ecKeyPEMtoJWK(String pem) throws PemException {
        JWK ecKey = PEMUtils.pemToECKey(pem);

        // Keys have been converted to PKCS#8 so PEM serialization is different
        String newPem = PEMUtils.jwkToPem(ecKey);
        JWK ecKey2 = PEMUtils.pemToECKey(newPem);

        assertThat(ecKey2).isEqualTo(ecKey);
    }

    @ParameterizedTest
    @MethodSource("com.blackberry.jwteditor.PEMToJWKTests#ecPublicValidPEMs")
    void publicEcKeyPEMtoJWK(String pem) throws PemException {
        JWK ecKey = PEMUtils.pemToECKey(pem);
        String newPem = PEMUtils.jwkToPem(ecKey);
        assertThat(newPem).isEqualTo(pem);
    }

    @ParameterizedTest
    @MethodSource("com.blackberry.jwteditor.JWKToPEMTests#ecPrivateValidJWKs")
    void privateEcJWKtoPEM(String jwkString) throws PemException, ParseException {
        ECKey ecKey = ECKey.parse(jwkString);
        String pem = PEMUtils.jwkToPem(ecKey);
        JWK newKey = PEMUtils.pemToECKey(pem);
        assertEqualsIgnoringWhitespaceAndKid(newKey.toJSONString(), jwkString);
    }

    @ParameterizedTest
    @MethodSource("com.blackberry.jwteditor.JWKToPEMTests#ecPublicValidJWKs")
    void publicEcJWKtoPEM(String jwkString) throws PemException, ParseException {
        ECKey ecKey = ECKey.parse(jwkString);
        String pem = PEMUtils.jwkToPem(ecKey);
        JWK newKey = PEMUtils.pemToECKey(pem);
        assertEqualsIgnoringWhitespaceAndKid(newKey.toJSONString(), jwkString);
    }

    @ParameterizedTest
    @MethodSource("com.blackberry.jwteditor.PEMToJWKTests#ocpPrivateValidPEMs")
    void privateOctetKeyPairPEMtoJWK(String pem) throws PemException {
        JWK octetKeyPair = PEMUtils.pemToOctetKeyPair(pem);
        String newPem = PEMUtils.jwkToPem(octetKeyPair);
        assertEqualsIgnoringPemHeaderAndFooter(newPem, pem);
    }

    @ParameterizedTest
    @MethodSource("com.blackberry.jwteditor.PEMToJWKTests#ocpPublicValidPEMs")
    void publicOctetKeyPairPEMtoJWK(String pem) throws PemException {

        JWK octetKeyPair = PEMUtils.pemToOctetKeyPair(pem);
        String newPem = PEMUtils.jwkToPem(octetKeyPair);
        assertEqualsIgnoringPemHeaderAndFooter(newPem, pem);
    }

    @ParameterizedTest
    @MethodSource("com.blackberry.jwteditor.JWKToPEMTests#ocpPrivateValidJWKs")
    void privateOctetKeyPairJWKtoPEM(String jwkString) throws PemException, ParseException {
        OctetKeyPair octetKeyPair = OctetKeyPair.parse(jwkString);
        String pem = PEMUtils.jwkToPem(octetKeyPair);
        JWK newKey = PEMUtils.pemToOctetKeyPair(pem);
        assertEqualsIgnoringWhitespaceAndKid(newKey.toJSONString(), jwkString);
    }

    @ParameterizedTest
    @MethodSource("com.blackberry.jwteditor.JWKToPEMTests#ocpPublicValidJWKs")
    void publicOctetKeyPairJWKtoPEM(String jwkString) throws PemException, ParseException {
        OctetKeyPair octetKeyPair = OctetKeyPair.parse(jwkString);
        String pem = PEMUtils.jwkToPem(octetKeyPair);
        JWK newKey = PEMUtils.pemToOctetKeyPair(pem);
        assertEqualsIgnoringWhitespaceAndKid(newKey.toJSONString(), jwkString);
    }

    private static void assertEqualsIgnoringWhitespaceAndKid(String jwkJson1, String jwkJson2) {
        String s1 = jwkJson1
                .replace(" ", "")
                .replaceFirst(KID_REGEX, "");

        String s2 = jwkJson2.replace(" ", "")
                .replace(" ", "")
                .replaceFirst(KID_REGEX, "");

        assertThat(s1).isEqualTo(s2);
    }

    private static String removePemHeaderAndFooters(String pem) {
        return pem.lines().filter(l -> !l.startsWith("-----")).collect(Collectors.joining("\n"));
    }

    private static void assertEqualsIgnoringPemHeaderAndFooter(String pem1, String pem2) {
        String s1 = removePemHeaderAndFooters(pem1);
        String s2 = removePemHeaderAndFooters(pem2);
        assertThat(s1).isEqualTo(s2);
    }
}
