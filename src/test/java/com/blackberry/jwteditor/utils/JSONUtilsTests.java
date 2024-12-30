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

package com.blackberry.jwteditor.utils;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.stream.Stream;

import static com.blackberry.jwteditor.utils.JSONUtils.*;
import static com.blackberry.jwteditor.utils.JsonData.COMPACTED_JSON;
import static com.blackberry.jwteditor.utils.JsonData.PRETTY_PRINTED_JSON;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class JSONUtilsTests {

    @ParameterizedTest
    @ValueSource(strings = {COMPACTED_JSON, PRETTY_PRINTED_JSON})
    void testCompactJSON(String json) {
        String compactedJSON = compactJSON(json);
        assertThat(compactedJSON).isEqualTo(COMPACTED_JSON);
    }

    @ParameterizedTest
    @ValueSource(strings = {COMPACTED_JSON, PRETTY_PRINTED_JSON})
    void testPrettyPrintJSON(String json) {
        String prettyPrintedJSON = JSONUtils.prettyPrintJSON(json);
        assertThat(prettyPrintedJSON).isEqualTo(PRETTY_PRINTED_JSON);
    }

    private static Stream<Arguments>  isJsonCompactData() {
        return Stream.of(
                arguments(PRETTY_PRINTED_JSON, false),
                arguments(COMPACTED_JSON, true)
        );
    }

    @MethodSource("isJsonCompactData")
    @ParameterizedTest
    void testIsJsonCompact(String json, boolean expectedIsJsonCompacted) {
        assertThat(isJsonCompact(json)).isEqualTo(expectedIsJsonCompacted);
    }

    private static Stream<Arguments>  isJsonObjectData() {
        return Stream.of(
                arguments(PRETTY_PRINTED_JSON, true),
                arguments(COMPACTED_JSON, true),
                arguments("", false),
                arguments("[]", false),
                arguments("null", false),
                arguments("string", false),
                arguments("448", false)
        );
    }

    @MethodSource("isJsonObjectData")
    @ParameterizedTest
    void testIsJsonObject(String json, boolean expectedIsJsonCompacted) {
        assertThat(isJsonObject(json)).isEqualTo(expectedIsJsonCompacted);
    }
}
