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

import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static com.blackberry.jwteditor.utils.JsonData.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class Base64URLUtilsTest {
    private static Stream<Arguments> data() {
        return Stream.of(
                arguments(COMPACTED_JSON, false, "eyJraWQiOiJkZmM2YTlkZi05MTZjLTQwNmQtODRkZS1jZTViNDlkNTBhZDAiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsImtpZCI6ImRmYzZhOWRmLTkxNmMtNDA2ZC04NGRlLWNlNWI0OWQ1MGFkMCIsIm4iOiJwMFUwTWRIRkxQb3ZYNWo5MW9ILWRjNTRvZUpESURhcHVQRE05Z1lIamhYMkJ3ajRmRmhxdmFBZklobi13N3ptLTZIWnNILVZ4UENuZ2w3R2tXeHgxRjdDb2JrZzhUT0Q0VXVzRkZvOHNyU0ZERXhXQ1E0TVJGRFJjTE45Ym1mWGVpUi1NdkdFMXRIWk5KQ09ueHN4MzItdWVGMFQyeG84ODAtMDczc2t1bThzUzl2aTdSdU5oYUNZX2xpSk5rcnpucVFDRWJOTFJfLVZfLUlRYUZHX29iRE5xRUhyb0tDM2x4ejM0czRDUHBVd2VuOElGSm04X3ZiY0ZpSV9qWnJ3X1ZUd0pNNElsNUhyMnVKTHZfYWhzWlRMb211bUptYWJ2WHVsZ1FGQks0aEVkLUZINGM3MmdsYkZmRkxFa3pSUXotb3pDenlTdWRiUkc5VXZodWJQeVEifX0"),
                arguments(COMPACTED_JSON, true, "eyJraWQiOiJkZmM2YTlkZi05MTZjLTQwNmQtODRkZS1jZTViNDlkNTBhZDAiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsImtpZCI6ImRmYzZhOWRmLTkxNmMtNDA2ZC04NGRlLWNlNWI0OWQ1MGFkMCIsIm4iOiJwMFUwTWRIRkxQb3ZYNWo5MW9ILWRjNTRvZUpESURhcHVQRE05Z1lIamhYMkJ3ajRmRmhxdmFBZklobi13N3ptLTZIWnNILVZ4UENuZ2w3R2tXeHgxRjdDb2JrZzhUT0Q0VXVzRkZvOHNyU0ZERXhXQ1E0TVJGRFJjTE45Ym1mWGVpUi1NdkdFMXRIWk5KQ09ueHN4MzItdWVGMFQyeG84ODAtMDczc2t1bThzUzl2aTdSdU5oYUNZX2xpSk5rcnpucVFDRWJOTFJfLVZfLUlRYUZHX29iRE5xRUhyb0tDM2x4ejM0czRDUHBVd2VuOElGSm04X3ZiY0ZpSV9qWnJ3X1ZUd0pNNElsNUhyMnVKTHZfYWhzWlRMb211bUptYWJ2WHVsZ1FGQks0aEVkLUZINGM3MmdsYkZmRkxFa3pSUXotb3pDenlTdWRiUkc5VXZodWJQeVEifX0"),
                arguments(PRETTY_PRINTED_JSON, false, "ewogICAgImtpZCI6ICJkZmM2YTlkZi05MTZjLTQwNmQtODRkZS1jZTViNDlkNTBhZDAiLAogICAgInR5cCI6ICJKV1QiLAogICAgImFsZyI6ICJSUzI1NiIsCiAgICAiandrIjogewogICAgICAgICJrdHkiOiAiUlNBIiwKICAgICAgICAiZSI6ICJBUUFCIiwKICAgICAgICAia2lkIjogImRmYzZhOWRmLTkxNmMtNDA2ZC04NGRlLWNlNWI0OWQ1MGFkMCIsCiAgICAgICAgIm4iOiAicDBVME1kSEZMUG92WDVqOTFvSC1kYzU0b2VKRElEYXB1UERNOWdZSGpoWDJCd2o0ZkZocXZhQWZJaG4tdzd6bS02SFpzSC1WeFBDbmdsN0drV3h4MUY3Q29ia2c4VE9ENFV1c0ZGbzhzclNGREV4V0NRNE1SRkRSY0xOOWJtZlhlaVItTXZHRTF0SFpOSkNPbnhzeDMyLXVlRjBUMnhvODgwLTA3M3NrdW04c1M5dmk3UnVOaGFDWV9saUpOa3J6bnFRQ0ViTkxSXy1WXy1JUWFGR19vYkROcUVIcm9LQzNseHozNHM0Q1BwVXdlbjhJRkptOF92YmNGaUlfalpyd19WVHdKTTRJbDVIcjJ1Skx2X2Foc1pUTG9tdW1KbWFidlh1bGdRRkJLNGhFZC1GSDRjNzJnbGJGZkZMRWt6UlF6LW96Q3p5U3VkYlJHOVV2aHViUHlRIgogICAgfQp9"),
                arguments(PRETTY_PRINTED_JSON, true, "eyJraWQiOiJkZmM2YTlkZi05MTZjLTQwNmQtODRkZS1jZTViNDlkNTBhZDAiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsImtpZCI6ImRmYzZhOWRmLTkxNmMtNDA2ZC04NGRlLWNlNWI0OWQ1MGFkMCIsIm4iOiJwMFUwTWRIRkxQb3ZYNWo5MW9ILWRjNTRvZUpESURhcHVQRE05Z1lIamhYMkJ3ajRmRmhxdmFBZklobi13N3ptLTZIWnNILVZ4UENuZ2w3R2tXeHgxRjdDb2JrZzhUT0Q0VXVzRkZvOHNyU0ZERXhXQ1E0TVJGRFJjTE45Ym1mWGVpUi1NdkdFMXRIWk5KQ09ueHN4MzItdWVGMFQyeG84ODAtMDczc2t1bThzUzl2aTdSdU5oYUNZX2xpSk5rcnpucVFDRWJOTFJfLVZfLUlRYUZHX29iRE5xRUhyb0tDM2x4ejM0czRDUHBVd2VuOElGSm04X3ZiY0ZpSV9qWnJ3X1ZUd0pNNElsNUhyMnVKTHZfYWhzWlRMb211bUptYWJ2WHVsZ1FGQks0aEVkLUZINGM3MmdsYkZmRkxFa3pSUXotb3pDenlTdWRiUkc5VXZodWJQeVEifX0"),
                arguments(INVALID_JSON, false, "ewogICAgImtpZCI6ICJkZmM2YTlkZi05MTZjLTQwNmQtODRkZS1jZTViNDlkNTBhZDAiLAogICAgInR5cCI6ICJKV1QiCg"),
                arguments(INVALID_JSON, true, "ewogICAgImtpZCI6ICJkZmM2YTlkZi05MTZjLTQwNmQtODRkZS1jZTViNDlkNTBhZDAiLAogICAgInR5cCI6ICJKV1QiCg")
        );
    }

    @MethodSource("data")
    @ParameterizedTest
    void givenNonCompact(String json, boolean compactJson, String encodedData) {
        Base64URL actual = Base64URLUtils.base64UrlEncodeJson(json, compactJson);

        assertThat(actual.toString()).isEqualTo(encodedData);
    }
}