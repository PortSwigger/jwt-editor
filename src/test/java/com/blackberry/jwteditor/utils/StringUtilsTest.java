/*
Author : Dolph Flynn

Copyright 2024 Dolph Flynn

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

package com.blackberry.jwteditor.utils;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class StringUtilsTest {
    private static Stream<Arguments> data() {
        return Stream.of(
                arguments(null, 'z', 0),
                arguments("", 'z', 0),
                arguments("abc", 'z', 0),
                arguments("zabc", 'z', 1),
                arguments("zabz", 'z', 2),
                arguments("abc reggegeg\0fwfwfwz", 'z', 1),
                arguments("abc zzzzz", 'z', 5)
        );
    }

    @MethodSource("data")
    @ParameterizedTest
    void testCountOccurrences(String data, char c, int expected) {
        int actual = StringUtils.countOccurrences(data, c);

        assertThat(actual).isEqualTo(expected);
    }
}