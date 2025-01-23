/*
Author : Dolph Flynn

Copyright 2025 Dolph Flynn

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

package com.blackberry.jwteditor.operations.weak;

import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.jose.JWSFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class WeakSecretTesterTest {
    private static Stream<Arguments> data() {
        return Stream.of(
                arguments("secret", false),
                arguments("secret1", true),
                arguments("secret2", false)
        );
    }

    @MethodSource("data")
    @ParameterizedTest
    void testFinder(String secret, boolean isCorrect) throws Exception {
        JWS jws = JWSFactory.parse("eyJraWQiOiI3OTJlMzRhNi0yMDk0LTQyNzAtODU1OS0zN2YwMDRkMmFiNGQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY3OTA4MTE5N30.4ED_93tUFMSvc-jhmnouTl_db20JhIlNj8GOMN5jAZU");

        WeakSecretTester tester = new WeakSecretTester(jws);

        assertThat(tester.isSecretCorrect(secret)).isEqualTo(isCorrect);
    }
}