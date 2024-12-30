/*
Author : Dolph Flynn

Copyright 2023 BlackBerry Limited

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
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Pair;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import utils.ArgumentUtils;

import java.util.List;
import java.util.stream.Stream;

import static com.blackberry.jwteditor.utils.PEMUtils.pemToRSAKey;
import static com.nimbusds.jose.EncryptionMethod.*;
import static com.nimbusds.jose.JWEAlgorithm.*;
import static data.PemData.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

@SuppressWarnings("deprecation")
class RSAEncryptionTests {
    private static final String TEST_JWS = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZXN0In0.WVLalefVZ5Rj991Cjgh0qBjKSIQaqC_CgN3b-30GKpQ";
    private static final List<JWEAlgorithm> ENCRYPTION_ALGORITHMS = List.of(
            RSA1_5,
            RSA_OAEP,
            RSA_OAEP_256
    );
    private static final List<EncryptionMethod> ENCRYPTION_METHODS = List.of(
            A128CBC_HS256,
            A128GCM,
            A192CBC_HS384,
            A192GCM,
            A256CBC_HS512,
            A256GCM
    );

    private static Stream<Arguments> canEncryptWithRSA() {
        return Stream.of(
                arguments(RSA512Public, false),
                arguments(RSA1024Public, false),
                arguments(RSA2048Public, true),
                arguments(RSA3072Public, true),
                arguments(RSA4096Public, true),
                arguments(RSA512Private, false),
                arguments(RSA1024Private, false),
                arguments(RSA2048Private, true),
                arguments(RSA3072Private, true),
                arguments(RSA4096Private, true)
        );
    }

    @ParameterizedTest
    @MethodSource("canEncryptWithRSA")
    void canOnlyEncryptWithRSAKeysWithAtLeast2048Bits(String pem, boolean canEncrypt) throws Exception {
        JWK rsaKey = pemToRSAKey(pem);
        JWKKey key = JWKKeyFactory.from(rsaKey);
        assertThat(key.canEncrypt()).isEqualTo(canEncrypt);
    }

    private static Stream<Arguments> canDecryptWithRSA() {
        return Stream.of(
                arguments(RSA512Public, false),
                arguments(RSA1024Public, false),
                arguments(RSA2048Public, false),
                arguments(RSA3072Public, false),
                arguments(RSA4096Public, false),
                arguments(RSA512Private, false),
                arguments(RSA1024Private, false),
                arguments(RSA2048Private, true),
                arguments(RSA3072Private, true),
                arguments(RSA4096Private, true)
        );
    }

    @ParameterizedTest
    @MethodSource("canDecryptWithRSA")
    void canOnlyDecryptWithPrivateRSAKeysWithAtLeast2048Bits(String pem, boolean canDecrypt) throws Exception {
        JWK rsaKey = pemToRSAKey(pem);
        JWKKey key = JWKKeyFactory.from(rsaKey);
        assertThat(key.canDecrypt()).isEqualTo(canDecrypt);
    }

    private static Stream<String> rsaKeys() {
        return Stream.of(
                RSA512Public,
                RSA1024Public,
                RSA2048Public,
                RSA3072Public,
                RSA4096Public,
                RSA512Private,
                RSA1024Private,
                RSA2048Private,
                RSA3072Private,
                RSA4096Private
        );
    }

    @ParameterizedTest
    @MethodSource("rsaKeys")
    void rsaKeysHaveCorrectEncryptionAlgorithms(String pem) throws Exception {
        JWK rsaKey = pemToRSAKey(pem);
        JWKKey key = JWKKeyFactory.from(rsaKey);

        JWEAlgorithm[] keyEncryptionKeyAlgorithms = key.getKeyEncryptionKeyAlgorithms();

        assertThat(keyEncryptionKeyAlgorithms).containsExactly(RSA1_5, RSA_OAEP, RSA_OAEP_256);
    }

    private static Stream<Arguments> rsaKeysAndAlgorithms() {
        return ArgumentUtils.cartesianProduct(rsaKeys().toList(), ENCRYPTION_ALGORITHMS);
    }

    @ParameterizedTest
    @MethodSource("rsaKeysAndAlgorithms")
    void rsaKeysHaveCorrectEncryptionMethods(String pem, JWEAlgorithm keyEncryptionKeyAlgorithm) throws Exception {
        JWK rsaKey = pemToRSAKey(pem);
        JWKKey key = JWKKeyFactory.from(rsaKey);

        EncryptionMethod[] keyEncryptionKeyAlgorithms = key.getContentEncryptionKeyAlgorithms(keyEncryptionKeyAlgorithm);

        assertThat(keyEncryptionKeyAlgorithms).containsExactly(
                A128GCM,
                A192GCM,
                A256GCM,
                A128CBC_HS256,
                A192CBC_HS384,
                A256CBC_HS512
        );
    }

    private static Stream<Arguments> rsaKeyPairsAndAlgorithms() throws Exception {
        List<Pair<JWK, JWK>> keyPairs = List.of(
                Pair.of(pemToRSAKey(RSA2048Public), pemToRSAKey(RSA2048Private)),
                Pair.of(pemToRSAKey(RSA3072Public), pemToRSAKey(RSA3072Private)),
                Pair.of(pemToRSAKey(RSA4096Public), pemToRSAKey(RSA4096Private))
        );

        return ArgumentUtils.cartesianProduct(keyPairs, ENCRYPTION_ALGORITHMS, ENCRYPTION_METHODS);
    }

    @ParameterizedTest
    @MethodSource("rsaKeyPairsAndAlgorithms")
    void rsaEncryptionConsistency(Pair<JWK, JWK> keyPair, JWEAlgorithm kek, EncryptionMethod cek) throws Exception {
        JWKKey publicKey = JWKKeyFactory.from(keyPair.getLeft());
        JWKKey privateKey = JWKKeyFactory.from(keyPair.getRight());

        JWE jwe = JWEFactory.encrypt(JWSFactory.parse(TEST_JWS), publicKey, kek, cek);
        JWS decrypt = jwe.decrypt(privateKey);

        assertThat(decrypt.serialize()).isEqualTo(TEST_JWS);
    }
}
