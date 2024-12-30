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
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.JWKKeyFactory;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static com.nimbusds.jose.EncryptionMethod.*;
import static com.nimbusds.jose.JWEAlgorithm.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class OctetEncryptionTests {
    private static final String TEST_JWS = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJMaWdodG1hbiJ9.cB5NQREgEHk47Zx5XRGWZ85eJ8SgmvBuKW5_Pm4Zo6o";

    private static Stream<OctetSequenceKey> octetSequenceKeys() throws JOSEException {
        return Stream.of(
                new OctetSequenceKeyGenerator(128).generate(),
                new OctetSequenceKeyGenerator(192).generate(),
                new OctetSequenceKeyGenerator(256).generate(),
                new OctetSequenceKeyGenerator(384).generate(),
                new OctetSequenceKeyGenerator(512).generate()
        );
    }

    @ParameterizedTest
    @MethodSource("octetSequenceKeys")
    void allOctetSequenceKeyCanEncrypt(OctetSequenceKey octKey) throws Exception {
        JWKKey key = JWKKeyFactory.from(octKey);
        assertThat(key.canEncrypt()).isTrue();
    }

    @ParameterizedTest
    @MethodSource("octetSequenceKeys")
    void allOctetSequenceKeyCanDecrypt(OctetSequenceKey octKey) throws Exception {
        JWKKey key = JWKKeyFactory.from(octKey);
        assertThat(key.canDecrypt()).isTrue();
    }

    private static Stream<Arguments> octetSequenceKeysAndExpectedAlgorithms() throws JOSEException {
        return Stream.of(
                arguments(new OctetSequenceKeyGenerator(128).generate(), List.of(DIR, A128KW, A128GCMKW)),
                arguments(new OctetSequenceKeyGenerator(192).generate(), List.of(DIR, A192KW, A192GCMKW)),
                arguments(new OctetSequenceKeyGenerator(256).generate(), List.of(DIR, A256KW, A256GCMKW)),
                arguments(new OctetSequenceKeyGenerator(384).generate(), List.of(DIR)),
                arguments(new OctetSequenceKeyGenerator(512).generate(), List.of(DIR))
        );
    }

    @ParameterizedTest
    @MethodSource("octetSequenceKeysAndExpectedAlgorithms")
    void octKeysHaveCorrectEncryptionAlgorithms(OctetSequenceKey octKey, List<JWEAlgorithm> expectedAlgorithms) throws Exception {
        JWKKey key = JWKKeyFactory.from(octKey);

        JWEAlgorithm[] keyEncryptionKeyAlgorithms = key.getKeyEncryptionKeyAlgorithms();

        assertThat(keyEncryptionKeyAlgorithms).containsExactlyElementsOf(expectedAlgorithms);
    }

    private static Stream<Arguments> octetSequenceKeysAndAlgorithm() throws JOSEException {
        OctetSequenceKey oct128 = new OctetSequenceKeyGenerator(128).generate();
        OctetSequenceKey oct192 = new OctetSequenceKeyGenerator(192).generate();
        OctetSequenceKey oct256 = new OctetSequenceKeyGenerator(256).generate();
        OctetSequenceKey oct384 = new OctetSequenceKeyGenerator(384).generate();
        OctetSequenceKey oct512 = new OctetSequenceKeyGenerator(512).generate();

        return Stream.of(
                arguments(oct128, DIR, List.of(A128GCM)),
                arguments(oct128, A128KW, List.of(A128GCM, A192GCM, A256GCM, A128CBC_HS256, A192CBC_HS384, A256CBC_HS512)),
                arguments(oct128, A128GCMKW, List.of(A128GCM, A192GCM, A256GCM, A128CBC_HS256, A192CBC_HS384, A256CBC_HS512)),
                arguments(oct192, DIR, List.of(A192GCM)),
                arguments(oct192, A192KW, List.of(A128GCM, A192GCM, A256GCM, A128CBC_HS256, A192CBC_HS384, A256CBC_HS512)),
                arguments(oct192, A192GCMKW, List.of(A128GCM, A192GCM, A256GCM, A128CBC_HS256, A192CBC_HS384, A256CBC_HS512)),
                arguments(oct256, DIR, List.of(A256GCM, A128CBC_HS256)),
                arguments(oct256, A256KW, List.of(A128GCM, A192GCM, A256GCM, A128CBC_HS256, A192CBC_HS384, A256CBC_HS512)),
                arguments(oct256, A256GCMKW, List.of(A128GCM, A192GCM, A256GCM, A128CBC_HS256, A192CBC_HS384, A256CBC_HS512)),
                arguments(oct384, DIR, List.of(A192CBC_HS384)),
                arguments(oct512, DIR, List.of(A256CBC_HS512))
        );
    }

    @ParameterizedTest
    @MethodSource("octetSequenceKeysAndAlgorithm")
    void octKeysHaveCorrectEncryptionMethods(OctetSequenceKey octKey, JWEAlgorithm keyEncryptionKeyAlgorithm, List<EncryptionMethod> expectedEncryptionMethod) throws Exception {
        JWKKey key = JWKKeyFactory.from(octKey);

        EncryptionMethod[] keyEncryptionKeyAlgorithms = key.getContentEncryptionKeyAlgorithms(keyEncryptionKeyAlgorithm);

        assertThat(keyEncryptionKeyAlgorithms).containsExactlyElementsOf(expectedEncryptionMethod);
    }

    private static Stream<Arguments> octKeysAndAlgorithms() throws Exception {
        OctetSequenceKey oct128 = new OctetSequenceKeyGenerator(128).generate();
        OctetSequenceKey oct192 = new OctetSequenceKeyGenerator(192).generate();
        OctetSequenceKey oct256 = new OctetSequenceKeyGenerator(256).generate();
        OctetSequenceKey oct384 = new OctetSequenceKeyGenerator(384).generate();
        OctetSequenceKey oct512 = new OctetSequenceKeyGenerator(512).generate();

        return Stream.of(
                arguments(oct128, DIR, A128GCM),
                arguments(oct128, A128KW, A128GCM),
                arguments(oct128, A128KW, A192GCM),
                arguments(oct128, A128KW, A256GCM),
                arguments(oct128, A128KW, A128CBC_HS256),
                arguments(oct128, A128KW, A192CBC_HS384),
                arguments(oct128, A128KW, A256CBC_HS512),
                arguments(oct128, A128GCMKW, A128GCM),
                arguments(oct128, A128GCMKW, A192GCM),
                arguments(oct128, A128GCMKW, A256GCM),
                arguments(oct128, A128GCMKW, A128CBC_HS256),
                arguments(oct128, A128GCMKW, A192CBC_HS384),
                arguments(oct128, A128GCMKW, A256CBC_HS512),
                arguments(oct192, DIR, A192GCM),
                arguments(oct192, A192KW, A128GCM),
                arguments(oct192, A192KW, A192GCM),
                arguments(oct192, A192KW, A256GCM),
                arguments(oct192, A192KW, A128CBC_HS256),
                arguments(oct192, A192KW, A192CBC_HS384),
                arguments(oct192, A192KW, A256CBC_HS512),
                arguments(oct192, A192GCMKW, A128GCM),
                arguments(oct192, A192GCMKW, A192GCM),
                arguments(oct192, A192GCMKW, A256GCM),
                arguments(oct192, A192GCMKW, A128CBC_HS256),
                arguments(oct192, A192GCMKW, A192CBC_HS384),
                arguments(oct192, A192GCMKW, A256CBC_HS512),
                arguments(oct256, DIR, A256GCM),
                arguments(oct256, A256KW, A128GCM),
                arguments(oct256, A256KW, A192GCM),
                arguments(oct256, A256KW, A256GCM),
                arguments(oct256, A256KW, A128CBC_HS256),
                arguments(oct256, A256KW, A192CBC_HS384),
                arguments(oct256, A256KW, A256CBC_HS512),
                arguments(oct256, DIR, A128CBC_HS256),
                arguments(oct256, A256GCMKW, A128GCM),
                arguments(oct256, A256GCMKW, A192GCM),
                arguments(oct256, A256GCMKW, A256GCM),
                arguments(oct256, A256GCMKW, A128CBC_HS256),
                arguments(oct256, A256GCMKW, A192CBC_HS384),
                arguments(oct256, A256GCMKW, A256CBC_HS512),
                arguments(oct384, DIR, A192CBC_HS384),
                arguments(oct512, DIR, A256CBC_HS512)
        );
    }

    @ParameterizedTest
    @MethodSource("octKeysAndAlgorithms")
    void octEncryptionConsistency(OctetSequenceKey octKey, JWEAlgorithm kek, EncryptionMethod cek) throws Exception {
        JWKKey key = JWKKeyFactory.from(octKey);

        JWE jwe = JWEFactory.encrypt(JWSFactory.parse(TEST_JWS), key, kek, cek);
        JWS decrypt = jwe.decrypt(key);

        assertThat(decrypt.serialize()).isEqualTo(TEST_JWS);
    }
}
