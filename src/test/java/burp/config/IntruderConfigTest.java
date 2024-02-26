/*
Author : Dolph Flynn

Copyright 2022 Dolph Flynn

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

package burp.config;

import burp.intruder.IntruderConfig;
import org.junit.jupiter.api.Test;

import static com.nimbusds.jose.JWSAlgorithm.HS256;
import static org.assertj.core.api.Assertions.assertThat;

class IntruderConfigTest {
    @Test
    void givenNullKeyID_whenResignIsSetTrue_thenResignIsFalse() {
        IntruderConfig config = new IntruderConfig();
        config.setSigningKeyId(null);

        config.setResign(true);

        assertThat(config.resign()).isFalse();
    }

    @Test
    void givenEmptyKeyID_whenResignIsSetTrue_thenResignIsFalse() {
        IntruderConfig config = new IntruderConfig();
        config.setSigningKeyId("");

        config.setResign(true);

        assertThat(config.resign()).isFalse();
    }

    @Test
    void givenValidKeyIDAndNullSigningAlgorithm_whenResignIsSetTrue_thenResignIsFalse() {
        IntruderConfig config = new IntruderConfig();
        config.setSigningKeyId("keyID");

        config.setResign(true);

        assertThat(config.resign()).isFalse();
    }

    @Test
    void givenValidKeyIDAndNonNullSigningAlgorithm_whenResignIsSetTrue_thenResignIsTrue() {
        IntruderConfig config = new IntruderConfig();
        config.setSigningKeyId("keyID");
        config.setSigningAlgorithm(HS256);

        config.setResign(true);

        assertThat(config.resign()).isTrue();
    }

    @Test
    void givenResignIsSetTrue_whenNullKeyID_thenResignIsFalse() {
        IntruderConfig config = new IntruderConfig();
        config.setSigningKeyId("keyId");
        config.setResign(true);

        config.setSigningKeyId(null);

        assertThat(config.resign()).isFalse();
    }

    @Test
    void givenResignIsSetTrue_whenEmptyKeyID_thenResignIsFalse() {
        IntruderConfig config = new IntruderConfig();
        config.setSigningKeyId("keyId");
        config.setResign(true);

        config.setSigningKeyId("");

        assertThat(config.resign()).isFalse();
    }
}