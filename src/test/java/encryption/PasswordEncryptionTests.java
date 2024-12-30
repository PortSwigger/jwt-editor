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

package encryption;

import com.blackberry.jwteditor.model.jose.JWE;
import com.blackberry.jwteditor.model.jose.JWEFactory;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.jose.JWSFactory;
import com.blackberry.jwteditor.model.keys.PasswordKey;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import utils.ArgumentUtils;

import java.util.List;
import java.util.stream.Stream;

import static com.nimbusds.jose.EncryptionMethod.*;
import static com.nimbusds.jose.JWEAlgorithm.*;
import static org.assertj.core.api.Assertions.assertThat;

class PasswordEncryptionTests {
    private static final String TEST_JWS = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJMaWdodG1hbiJ9.cB5NQREgEHk47Zx5XRGWZ85eJ8SgmvBuKW5_Pm4Zo6o";
    private static final List<JWEAlgorithm> ENCRYPTION_ALGORITHMS = List.of(PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW);
    private static final List<EncryptionMethod> ENCRYPTION_METHODS = List.of(
            A128GCM, A192GCM, A256GCM, A128CBC_HS256, A128CBC_HS256_DEPRECATED, A192CBC_HS384, A256CBC_HS512, A256CBC_HS512_DEPRECATED
    );

    private static final PasswordKey KEY = new PasswordKey("testKeyId", "secret", 8, 1337);

    @Test
    void passwordKeyCanEncrypt() {
        assertThat(KEY.canEncrypt()).isTrue();
    }

    @Test
    void passwordKeyCanDecrypt() {
        assertThat(KEY.canDecrypt()).isTrue();
    }

    @Test
    void octKeysHaveCorrectEncryptionAlgorithms() {
        JWEAlgorithm[] keyEncryptionKeyAlgorithms = KEY.getKeyEncryptionKeyAlgorithms();

        assertThat(keyEncryptionKeyAlgorithms).containsExactlyElementsOf(ENCRYPTION_ALGORITHMS);
    }

    private static Stream<JWEAlgorithm> encryptionAlgorithms() {
        return ENCRYPTION_ALGORITHMS.stream();
    }

    @ParameterizedTest
    @MethodSource("encryptionAlgorithms")
    void octKeysHaveCorrectEncryptionMethods(JWEAlgorithm keyEncryptionKeyAlgorithm){
        EncryptionMethod[] keyEncryptionKeyAlgorithms = KEY.getContentEncryptionKeyAlgorithms(keyEncryptionKeyAlgorithm);

        assertThat(keyEncryptionKeyAlgorithms).containsExactlyElementsOf(ENCRYPTION_METHODS);
    }

    private static Stream<Arguments> algorithmsAndMethods() {
        return ArgumentUtils.cartesianProduct(ENCRYPTION_ALGORITHMS, ENCRYPTION_METHODS);
    }

    @ParameterizedTest
    @MethodSource("algorithmsAndMethods")
    void passwordEncryptionConsistency(JWEAlgorithm kek, EncryptionMethod cek) throws Exception {
        JWE jwe = JWEFactory.encrypt(JWSFactory.parse(TEST_JWS), KEY, kek, cek);
        JWS decrypt = jwe.decrypt(KEY);

        assertThat(decrypt.serialize()).isEqualTo(TEST_JWS);
    }
}
