/*
Author : Dolph Flynn

Copyright 2026 Dolph Flynn

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

package com.blackberry.jwteditor.pem;

import com.blackberry.jwteditor.pem.PemKey.NewLineStrategy;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static com.blackberry.jwteditor.pem.PemKey.NewLineStrategy.*;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class PemKeyTest {
    private static final String SYSTEM_LINE_SEPARATOR = System.lineSeparator();

    @Test
    void givenPemObjectWithoutHeaders_whenConvertedToString_thenUsingTheSystemLineSeparatorByDefault() {
        PemObject object = new PemObject("TEST", "content".getBytes(US_ASCII));

        String serialized = new PemKey(object).toString();

        assertThat(serialized).isEqualTo("-----BEGIN TEST-----%sY29udGVudA==%s-----END TEST-----%s".formatted(SYSTEM_LINE_SEPARATOR, SYSTEM_LINE_SEPARATOR, SYSTEM_LINE_SEPARATOR));
    }

    private static Stream<Arguments> trailingNewLineData() {
        return Stream.of(
                arguments(SYSTEM_DEFAULT, SYSTEM_LINE_SEPARATOR),
                arguments(LINUX_MACOS, "\n"),
                arguments(WINDOWS, "\r\n")
        );
    }

    private static Stream<Arguments> noTrailingNewLineData() {
        return Stream.of(
                arguments(LINUX_MACOS_NO_TRAILING_LINE, "\n"),
                arguments(WINDOWS_NO_TRAILING_LINE, "\r\n")
        );
    }

    @MethodSource("trailingNewLineData")
    @ParameterizedTest
    void givenPemObjectWithoutHeaders_whenConvertedToStringUsingNewLineStrategy_thenOutputCorrect(NewLineStrategy strategy, String newLine) {
        PemObject object = new PemObject("TEST", new byte[]{0, 1, 2, 3});

        String serialized = new PemKey(object).toString(strategy);

        assertThat(serialized).isEqualTo("-----BEGIN TEST-----%sAAECAw==%s-----END TEST-----%s".formatted(newLine, newLine, newLine));
    }

    @MethodSource("noTrailingNewLineData")
    @ParameterizedTest
    void givenPemObjectWithoutHeaders_whenConvertedToStringUsingNewLineStrategyWithNoTrailingNewLine_thenOutputCorrect(NewLineStrategy strategy, String newLine) {
        PemObject object = new PemObject("TEST", new byte[]{0, 1, 2, 3});

        String serialized = new PemKey(object).toString(strategy);

        assertThat(serialized).isEqualTo("-----BEGIN TEST-----%sAAECAw==%s-----END TEST-----".formatted(newLine, newLine));
    }

    @Test
    void givenPemObjectWithHeaders_whenConvertedToString_thenUsingTheSystemLineSeparatorByDefault() {
        List<PemHeader> headers = List.of(
                new PemHeader("Name1", "Value1"),
                new PemHeader("Name2", "Value2"));
        PemObject object = new PemObject("TEST", headers, new byte[]{0});

        String serialized = new PemKey(object).toString();

        assertThat(serialized).isEqualTo("-----BEGIN TEST-----%sName1: Value1%sName2: Value2%s%sAA==%s-----END TEST-----%s".formatted(SYSTEM_LINE_SEPARATOR, SYSTEM_LINE_SEPARATOR, SYSTEM_LINE_SEPARATOR, SYSTEM_LINE_SEPARATOR, SYSTEM_LINE_SEPARATOR, SYSTEM_LINE_SEPARATOR));
    }

    @MethodSource("trailingNewLineData")
    @ParameterizedTest
    void givenPemObjectWithHeaders_whenConvertedToStringUsingNewLineStrategy_thenOutputCorrect(NewLineStrategy strategy, String newLine) {
        List<PemHeader> headers = List.of(
                new PemHeader("Name1", "Value1"),
                new PemHeader("Name2", "Value2"));
        PemObject object = new PemObject("TEST", headers, new byte[]{0});

        String serialized = new PemKey(object).toString(strategy);

        assertThat(serialized).isEqualTo("-----BEGIN TEST-----%sName1: Value1%sName2: Value2%s%sAA==%s-----END TEST-----%s".formatted(newLine, newLine, newLine, newLine, newLine, newLine));
    }

    @MethodSource("noTrailingNewLineData")
    @ParameterizedTest
    void givenPemObjectWithHeaders_whenConvertedToStringUsingNewLineStrategyWithNoTrailingNewLine_thenOutputCorrect(NewLineStrategy strategy, String newLine) {
        List<PemHeader> headers = List.of(
                new PemHeader("Name1", "Value1"),
                new PemHeader("Name2", "Value2"));
        PemObject object = new PemObject("TEST", headers, new byte[]{0});

        String serialized = new PemKey(object).toString(strategy);

        assertThat(serialized).isEqualTo("-----BEGIN TEST-----%sName1: Value1%sName2: Value2%s%sAA==%s-----END TEST-----".formatted(newLine, newLine, newLine, newLine, newLine));
    }

    @Test
    void givenPemObjectWithLargerContent_whenConvertedToStringUsingSystemDefaultSeparator_thenOutputWrapsCorrect() {
        byte[] content = "a".repeat(49).getBytes();
        PemObject pemObject = new PemObject("TEST", content);

        String serialized = new PemKey(pemObject).toString(SYSTEM_DEFAULT);

        assertThat(serialized).isEqualTo("-----BEGIN TEST-----%sYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh%sYQ==%s-----END TEST-----%s", SYSTEM_LINE_SEPARATOR, SYSTEM_LINE_SEPARATOR, SYSTEM_LINE_SEPARATOR, SYSTEM_LINE_SEPARATOR);
    }
}
