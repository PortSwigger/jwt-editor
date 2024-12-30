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

package attack;

import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.jose.JWSFactory;
import com.blackberry.jwteditor.operations.Attacks;
import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static com.nimbusds.jose.JWSAlgorithm.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class EmptySymmetricKeyAttackTest {
    private static final String TEST_JWS = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";

    private static Stream<Arguments> algorithmsAndExpectedJWTs() {
        return Stream.of(
                arguments(HS256, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.oTuz7VlZeiZC4qdezf5GGy0m9pkf4h8EzMiUcmCDQWM"),
                arguments(HS384, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.0K107TcoYCPrHKlESZrWUr3ueI3K083hxdPc_HIUp80pAAr7aJ0DVMOmK_xl0CoS"),
                arguments(HS512, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.uI7lKcbiA2Fa4XZkVrYw1FNMbUCMf25Ar2bTQaGd4bZ-vkQtMJln92HnvofHjD0lhL9-timtCSKYQSiZeI-kDw")
        );
    }

    @ParameterizedTest
    @MethodSource("algorithmsAndExpectedJWTs")
    void canSignJWSUsingEmptySymmetricKeys(JWSAlgorithm algorithm, String expectedJWT) throws Exception {
        JWS jws = JWSFactory.parse(TEST_JWS);

        JWS attackJws = Attacks.signWithEmptyKey(jws, algorithm);

        assertThat(attackJws.serialize()).isEqualTo(expectedJWT);
    }

    @Test
    void givenJWSWithBackslash_whenSignedWithEmptyKeyAndSameAlgorithm_thenHeaderInvariant() throws Exception {
        JWS jws = JWSFactory.parse("eyJraWQiOiIvZGV2L251bGwiLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.PsINWgUhM_MIthLdmb6OcMm5wMx4tuOnEdRj4W5RkxU");

        JWS attackJws = Attacks.signWithEmptyKey(jws, HS256);

        assertThat(attackJws.header().decoded()).isEqualTo(jws.header().decoded());
    }

    private static Stream<JWSAlgorithm> unsupportedAlgorithms() {
        return Stream.of(
                RS256, RS384, RS512,
                ES256, ES384, ES512,
                PS256, PS384, PS512,
                EdDSA
        );
    }

    @ParameterizedTest
    @MethodSource("unsupportedAlgorithms")
    void canSignJWSUsingEmptySymmetricKeys(JWSAlgorithm algorithm) throws Exception {
        JWS jws = JWSFactory.parse(TEST_JWS);

        assertThrows(IllegalArgumentException.class, () -> Attacks.signWithEmptyKey(jws, algorithm));
    }
}
