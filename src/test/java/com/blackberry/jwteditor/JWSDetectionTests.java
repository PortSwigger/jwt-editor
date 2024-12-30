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

import com.blackberry.jwteditor.model.jose.JOSEObject;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.jose.MutableJOSEObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static com.blackberry.jwteditor.model.jose.JOSEObjectFinder.*;
import static org.assertj.core.api.Assertions.assertThat;

class JWSDetectionTests {
    private static Stream<String> validJws() {
        return Stream.of(
                // JWS
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZXN0In0.Nabf3xakZubPnCzHT-fx0vG1iuNPeJKuSzHxUiQKf-8",
                // JWS without signature
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZXN0In0.",
                // JWS with empty payload
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyB9.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyAgfQ.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSH",
                // JWS with text claims
                "eyJhbGciOiJSUzI1NiIsImtpZCI6InlmdTlwUzlTaXVDZzNiaXZvZXZuNkxmZEZ2NUlMZk9wT3RsNnRCYmRlemsifQ.dXNlcg.soNtldMC7sxtVPSxkgvd7L7wPZ2FTMRvP-xgOjM5fQ3N74GeZZEKDzjaKeJ10EBeE4OcQkJeyawk5zmra65Nosc3BWDFieA7qUokVvW6qmKKnk7AoeBexirwVurAz4iOsaH5TQ_5Vwou1A2yHZSbuPBdq-Ofat9KKH5mo86yvLrEy2M3ikvOOJ3PFU49jLH9o1uCUCBKo-9g6B22b-q8Xwpt3faPa5RX0P6ihYt0wtsa4VecagLZyjDxfG46xWs7-aWpEi7pymGJdyLcD3ioUE5X6AbIIo7b73xfxLj4yjBjm-WROfPd4n82mh276ZHmEkw2F8eKYcWUp2YdPvZRyA",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.K0FIc0FJZy1zdWIrQUNJOitBQ0ktVGVzdCtBQ0lBZlEt.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9._v8AewAiAHMAdQBiACIAOgAiAFQAZQBzAHQAIgB9.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                // Payload not JSON object
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.bnVsbA.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.NDQ4.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.InNhdW5hIg.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.W10.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSH"
        );
    }

    private static Stream<String> invalidJws() {
        return Stream.of(
                "",
                ".",
                "...",
                "asdadasdasdeyJhbGci$iJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZXN0In0.Nabf3xakZubPnCzHT-fx0vG1iuNPeJKuSzHxUiQKf-8",
                "asdadasdasdeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ^ZXN0In0.Nabf3xakZubPnCzHT-fx0vG1iuNPeJKuSzHxUiQKf-8",
                // No header
                ".eyJzdWIiOiJUZXN0In0.Nabf3xakZubPnCzHT-fx0vG1iuNPeJKuSzHxUiQKf-8",
                // No payload
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..Nabf3xakZubPnCzHT-fx0vG1iuNPeJKuSzHxUiQKf-8",
                // Empty
                "..",
                //URL
                "www.blackberry.com",
                // Invalid charset encoding
                "K0FIc0FJZy10eXArQUNJOitBQ0ktSldUK0FDSSwrQUNJLWFsZytBQ0k6K0FDSS1IUzI1NitBQ0lBZlEt.eyJzdWIiOiJUZXN0In0.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                "_v8AewAiAHQAeQBwACIAOgAiAEoAVwBUACIALAAiAGEAbABnACIAOgAiAEgAUwAyADUANgAiAH0.eyJzdWIiOiJUZXN0In0.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                // Missing or invalid 'alg'
                "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJUZXN0In0.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiIifQ.eyJzdWIiOiJUZXN0In0.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiIgIn0.eyJzdWIiOiJUZXN0In0.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiIgICAgIn0.eyJzdWIiOiJUZXN0In0.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                "eyJ0eXAiOiJKV1QiLCJhbGciOm51bGx9.eyJzdWIiOiJUZXN0In0.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                "eyJ0eXAiOiJKV1QiLCJhbGciOjQ0OH0.eyJzdWIiOiJUZXN0In0.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                "eyJ0eXAiOiJKV1QiLCJhbGciOltdfQ.eyJzdWIiOiJUZXN0In0.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                "eyJ0eXAiOiJKV1QiLCJhbGciOnt9fQ.eyJzdWIiOiJUZXN0In0.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw",
                // Partial JWE
                "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0.H3X6mT5HLgcFfzLoe4ku6Knhh9Ofv1eL.qF5-N_7K8VQ4yMSz.",
                "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0.H3X6mT5HLgcFfzLoe4ku6Knhh9Ofv1eL.qF5-N_7K8VQ4yMSz.WXUNY6eg5fR4tc8Hqf5XDRM9ALGwcQyYG4IYwwg8Ctkx1UuxoV7t6UnemjzCj2sOYUqi3KYpDzrKVJpzokz0vcIem4lFe5N_ds8FAMpW0GSF9ePA8qvV99WaP0N2ECVPmgihvL6qwNhdptlLKtxcOpE41U5LnU22voPK55VF4_1j0WmTgWgZ7DwLDysp6EIDjrrt-DY."
        );
    }

    @ParameterizedTest
    @MethodSource("validJws")
    void testExtractValidJWS(String joseObjectString) {
        List<MutableJOSEObject> joseObjects = extractJOSEObjects(joseObjectString);

        assertThat(joseObjects).hasSize(1);
        assertThat(joseObjects.getFirst().getModified()).isInstanceOf(JWS.class);
    }

    @ParameterizedTest
    @MethodSource("validJws")
    void testExtractValidJWSWithWhitespace(String joseObjectString) {
        String text = " " + joseObjectString + " ";
        List<MutableJOSEObject> joseObjects = extractJOSEObjects(text);

        assertThat(joseObjects).hasSize(1);
        assertThat(joseObjects.getFirst().getModified()).isInstanceOf(JWS.class);
    }

    @ParameterizedTest
    @MethodSource("validJws")
    void testExtractValidJWSFromWithinData(String joseObjectString) {
        String text = "Authorization: Bearer " + joseObjectString + "\r\n";
        List<MutableJOSEObject> joseObjects = extractJOSEObjects(text);

        assertThat(joseObjects).hasSize(1);
        assertThat(joseObjects.getFirst().getModified()).isInstanceOf(JWS.class);
    }

    @ParameterizedTest
    @MethodSource("invalidJws")
    void testExtractInValidJWS(String joseObjectString) {
        List<MutableJOSEObject> joseObjects = extractJOSEObjects(joseObjectString);

        assertThat(joseObjects).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("validJws")
    void testDetectValidJWS(String joseObjectString) {
        assertThat(containsJOSEObjects(joseObjectString)).isTrue();
    }

    @ParameterizedTest
    @MethodSource("validJws")
    void testDetectValidJWSWithWhitespace(String joseObjectString) {
        String text = " " + joseObjectString + " ";
        assertThat(containsJOSEObjects(text)).isTrue();
    }

    @ParameterizedTest
    @MethodSource("validJws")
    void testDetectValidJWSFromWithinData(String joseObjectString) {
        String text = "Authorization: Bearer " + joseObjectString + "\r\n";

        assertThat(containsJOSEObjects(text)).isTrue();
    }

    @ParameterizedTest
    @MethodSource("invalidJws")
    void testDetectInvalidJWS(String joseObjectString) {
        assertThat(containsJOSEObjects(joseObjectString)).isFalse();
    }

    @ParameterizedTest
    @MethodSource("validJws")
    void testParseValidJWS(String joseObjectString) {
        Optional<JOSEObject> joseObject = parseJOSEObject(joseObjectString);

        assertThat(joseObject).isPresent();
        assertThat(joseObject.get()).isInstanceOf(JWS.class);
    }

    @ParameterizedTest
    @MethodSource("validJws")
    void testParseValidJWSFromWithinData(String joseObjectString) {
        String text = "Authorization: Bearer " + joseObjectString + "\r\n";

        Optional<JOSEObject> joseObject = parseJOSEObject(text);

        assertThat(joseObject).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("invalidJws")
    void testParseInvalidJWS(String joseObjectString) {
        Optional<JOSEObject> joseObject = parseJOSEObject(joseObjectString);

        assertThat(joseObject).isEmpty();
    }

    @Test
    void testParseMultipleJWS() {
        String jws1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZXN0In0.Nabf3xakZubPnCzHT-fx0vG1iuNPeJKuSzHxUiQKf-8";
        String jws2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZXN0In0.";
        String jws3 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.17DlZn0zeYhz3uTQCRpSx9hYlUj1SJxDMeZLof8dSHw";
        String data = jws1 + " " + jws2 + " " + jws3;

        List<MutableJOSEObject> joseObjects = extractJOSEObjects(data);

        assertThat(joseObjects).extracting("original").containsExactly(jws1, jws2, jws3);
    }
}
