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

package com.blackberry.jwteditor.model.jose;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.text.ParseException;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class JWSInformationTest {

    @BeforeAll
    static void setTimeZone() {
        System.setProperty("user.timezone", "UTC");
    }

    @Test
    void givenJWSWithNoTimeClaims_thenInformationIsEmpty() throws ParseException {
        JWS jws = JWSFactory.parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZXN0In0.WVLalefVZ5Rj991Cjgh0qBjKSIQaqC_CgN3b-30GKpQ");

        assertThat(jws.information()).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNzE2MjM5MDIyfQ.FuJB22Dq3zXcFXtIAc59tWnmbbFC6jRXzb_2ejbhhoQ",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoiMTcxNjIzOTAyMiJ9.8Tm8e1DEoD92S98fm9Hh_xFMsFVGNN7VjRZppD-bfMM"
    })
    void givenJWSWithExpTimeClaims_thenInformationCorrect(String data) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        Information information = jws.information().getFirst();

        assertThat(information.text()).isEqualTo("Expiration Time - Mon May 20 2024 21:03:42 GMT");
        assertThat(information.isWarning()).isTrue();
    }

    private static Stream<Arguments> jwsWithValidExpValues() {
        return Stream.of(
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoyMzE2MjM5MDIyfQ.nmCDcUHT-yLgrRG1LKMH9E2FQs2xWcB8CncxoqKdQEQ", "Expiration Time - Tue May 26 2043 07:43:42 GMT"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoiMjMxNjIzOTAyMiJ9.kDOLZJTcFVwrSVSDeFK31EIx7Q4e4Ya33iNCk4QZ10c", "Expiration Time - Tue May 26 2043 07:43:42 GMT"),
                arguments("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoiMjAzNi0xMi0xOVQxNjozOTo1Ny0wODowMCJ9.", "Expiration Time - Sat Dec 20 2036 00:39:57 GMT")
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithValidExpValues")
    void givenJWSWithExpTimeClaims_whenExpiryDateInTheFuture_thenInformationCorrect(String data, String expectedText) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        Information information = jws.information().getFirst();

        assertThat(information.text()).isEqualTo(expectedText);
        assertThat(information.isWarning()).isFalse();
    }

    private static Stream<Arguments> jwsWithInvalidExpValues() {
        return Stream.of(
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoiemVvbGl0ZSJ9.Vsy0uiJVpA17ys9DRFWldEcgiut_N5QhvHCRRcp8Xow", "Expiration Time - invalid value: zeolite"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjpudWxsfQ.JsGUzIiM3S7cZF3LjYg-S6rYz4VXK-GBpGELzNJKOgY", "Expiration Time - invalid value: null"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjotMTIzNDV9.BCgzT_CEurIxa0MxbS9seJ62lgfJT54P7AQpUkp65GE", "Expiration Time - invalid value: -12345")
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithInvalidExpValues")
    void givenJWSWithExpTimeClaims_whenExpiryDateInvalid_thenInformationCorrect(String data, String expectedText) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        Information information = jws.information().getFirst();

        assertThat(information.text()).isEqualTo(expectedText);
        assertThat(information.isWarning()).isTrue();
    }

    private static Stream<Arguments> jwsWithExpValuesInThePast() {
        return Stream.of(
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJleHAiOjE1MTYyMzkwMjJ9.mVGXFv3OuwtuZPsdaf_oGUYm2uOH-T-JRTDQE1c10q0", "Expiration Time - Thu Jan 18 2018 01:30:22 GMT"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJleHAiOjB9.eVVhRMapPD77WuMWIHKBqYw0cjJHC49On-mHEuonYjk", "Expiration Time - Thu Jan 01 1970 00:00:00 GMT")
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithExpValuesInThePast")
    void givenJWSWithExpTimeClaims_whenExpiryDateIsInThePast_thenInformationCorrect(String data, String expectedText) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        Information information = jws.information().getFirst();

        assertThat(information.text()).isEqualTo(expectedText);
        assertThat(information.isWarning()).isTrue();
    }


    @ParameterizedTest
    @ValueSource(strings = {
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjoxNzE2MjM5MDIyfQ.mZ_wGwRA0BBp_m6LJOPOBfwMosKrhTf9DbnKZYTzBzg",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjoiMTcxNjIzOTAyMiJ9.JD7t6jE6sOzuaFi5Lj5e3RhnoRDDWW9QHv_U3bFgEKM"
    })
    void givenJWSWithNbfTimeClaims_thenInformationCorrect(String data) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        Information information = jws.information().getFirst();

        assertThat(information.text()).isEqualTo("Not Before - Mon May 20 2024 21:03:42 GMT");
        assertThat(information.isWarning()).isFalse();
    }

    private static Stream<Arguments> jwsWithValidNbfValues() {
        return Stream.of(
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjoxNzE2MjM5MDIyfQ.mZ_wGwRA0BBp_m6LJOPOBfwMosKrhTf9DbnKZYTzBzg", "Not Before - Mon May 20 2024 21:03:42 GMT"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjoiMTcxNjIzOTAyMiJ9.JD7t6jE6sOzuaFi5Lj5e3RhnoRDDWW9QHv_U3bFgEKM", "Not Before - Mon May 20 2024 21:03:42 GMT"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJuYmYiOjE1MTYyMzkwMjJ9.1OhNEYnVM64dytXGZ1kj_Z3fV73xGFxWyba52S5r7wc", "Not Before - Thu Jan 18 2018 01:30:22 GMT"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJuYmYiOjB9.AqIAHlKSdpcDp7mD6sWsfKCQxI2hyJYsI7Y4Dh6N6pI", "Not Before - Thu Jan 01 1970 00:00:00 GMT"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJuYmYiOjE3MjIxNjc0Nzd9.2almhOGrigs8lXH9DLKBkkUCS6r5j7zpJXYsXJN39d4", "Not Before - Sun Jul 28 2024 11:51:17 GMT"),
                arguments("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjoiMjAyNC0wNS0yMFQyMjowMzo0MiswMTowMCJ9.", "Not Before - Mon May 20 2024 21:03:42 GMT")
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithValidNbfValues")
    void givenJWSWithNbfTimeClaims_whenNotBeforeDateInThePast_thenInformationCorrect(String data, String expectedText) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        Information information = jws.information().getFirst();

        assertThat(information.text()).isEqualTo(expectedText);
        assertThat(information.isWarning()).isFalse();
    }

    private static Stream<Arguments> jwsWithInvalidNbfValues() {
        return Stream.of(
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjoiemVvbGl0ZSJ9.kmx4FteQrcATfc2Zx47WypsqrIC-e1IM4opeLJxLyrI", "Not Before - invalid value: zeolite"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjpudWxsfQ.Nyai4iIAzjR5OcUwaE8xQYbArYuBIzbKxaJDnvu1J_I", "Not Before - invalid value: null"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjotMTIzNDV9.rlnrK7unNEaaghPFhNQnDp1GRbCU0rGORO2yDf5YIZk", "Not Before - invalid value: -12345")
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithInvalidNbfValues")
    void givenJWSWithNbfTimeClaims_whenNotBeforeDateInvalid_thenInformationCorrect(String data, String expectedText) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        Information information = jws.information().getFirst();

        assertThat(information.text()).isEqualTo(expectedText);
        assertThat(information.isWarning()).isTrue();
    }

    private static Stream<Arguments> jwsWithFutureNbfValues() {
        return Stream.of(
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJuYmYiOjIzMjIxNjc0Nzd9.cMocfo6ghvuYBqDwZ9GBdfbCnMLsUcZe2GZRuaah0-c", "Not Before - Sun Aug 02 2043 22:31:17 GMT"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJuYmYiOjE4MjIxNjc0Nzd9._m-Rhio9DLcVRfWo7S-KIvlTk29QuDgal-tqreN4y4E", "Not Before - Tue Sep 28 2027 21:37:57 GMT")
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithFutureNbfValues")
    void givenJWSWithNbfTimeClaims_whenNotBeforeDateIsInTheFuture_thenInformationCorrect(String data, String expectedText) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        Information information = jws.information().getFirst();

        assertThat(information.text()).isEqualTo(expectedText);
        assertThat(information.isWarning()).isTrue();
    }


    private static Stream<Arguments> jwsWithValidIatValues() {
        return Stream.of(
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE3MTYyMzkwMjJ9.y06rqsXv0DMutukwDaUJU0Sf-Ye3qrDkyFpOaj1J08A", "Issued At - Mon May 20 2024 21:03:42 GMT"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOiIxNzE2MjM5MDIyIn0.c2Ogr8QeTwopupVPqI56VaovZXE3svug2BI-Trft2EA", "Issued At - Mon May 20 2024 21:03:42 GMT")
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithValidIatValues")
    void givenJWSWithIatTimeClaims_thenInformationCorrect(String data, String expectedText) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        Information information = jws.information().getFirst();

        assertThat(information.text()).isEqualTo(expectedText);
        assertThat(information.isWarning()).isFalse();
    }


    private static Stream<Arguments> jwsWithValidIatDatesInThePast() {
        return Stream.of(
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE3MTYyMzkwMjJ9.y06rqsXv0DMutukwDaUJU0Sf-Ye3qrDkyFpOaj1J08A", "Issued At - Mon May 20 2024 21:03:42 GMT"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOiIxNzE2MjM5MDIyIn0.c2Ogr8QeTwopupVPqI56VaovZXE3svug2BI-Trft2EA", "Issued At - Mon May 20 2024 21:03:42 GMT"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.hqWGSaFpvbrXkOWc6lrnffhNWR19W_S1YKFBx2arWBk", "Issued At - Thu Jan 18 2018 01:30:22 GMT"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjB9.9TaucSjKgR3_gXUlzTGperv3PK9IAXO0ZVbgP9Wx4IY", "Issued At - Thu Jan 01 1970 00:00:00 GMT"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE3MjIxNjc0Nzd9.SWmvLUBWE5ddBWvSEWnrHM8W3rfzyYmEQVk6-ywFFgQ", "Issued At - Sun Jul 28 2024 11:51:17 GMT"),
                arguments("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoiMjAyNC0wNS0yMFQyMjowMzo0MiswMTowMCJ9.", "Issued At - Mon May 20 2024 21:03:42 GMT")
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithValidIatDatesInThePast")
    void givenJWSWithIatTimeClaims_whenIssuedAtDateInThePast_thenInformationCorrect(String data, String expectedText) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        Information information = jws.information().getFirst();

        assertThat(information.text()).isEqualTo(expectedText);
        assertThat(information.isWarning()).isFalse();
    }

    private static Stream<Arguments> jwsWithInvalidIatValues() {
        return Stream.of(
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOiJ6ZW9saXRlIn0.-IpgDK_M_jQJQ6FDa-wd25xGFJ2bHNthdYn1JlQNxjg", "Issued At - invalid value: zeolite"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOm51bGx9.uplfi-hImBCsHTs__K-0LU612y3EW92J1TbINlDGc-k", "Issued At - invalid value: null"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOi0xMjM0NX0.gVkVHyEasqw2NZ63un0T9Yd6bW8bmY9uMYndlptiQzQ", "Issued At - invalid value: -12345")
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithInvalidIatValues")
    void givenJWSWithIatTimeClaims_whenIssuedAtDateInvalid_thenInformationCorrect(String data, String expectedText) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        Information information = jws.information().getFirst();

        assertThat(information.text()).isEqualTo(expectedText);
        assertThat(information.isWarning()).isTrue();
    }


    private static Stream<Arguments> jwsWithFutureIatDates() {
        return Stream.of(
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjIzMjIxNjc0Nzd9.3UYGoLpdXRhnlai81VFV_iWmW90xnCimcYverY1-Zk4", "Issued At - Sun Aug 02 2043 22:31:17 GMT"),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE4MjIxNjc0Nzd9._H-G7WjMbg8IVADVbz1Lsd7I_bGQZBYKPf8S2Q9vxf4", "Issued At - Tue Sep 28 2027 21:37:57 GMT")
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithFutureIatDates")
    void givenJWSWithIatTimeClaims_whenIssuedAtDateIsInTheFuture_thenInformationCorrect(String data, String expectedText) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        Information information = jws.information().getFirst();

        assertThat(information.text()).isEqualTo(expectedText);
        assertThat(information.isWarning()).isTrue();
    }

    @Test
    void givenJWE_thenInformationIsEmpty() throws ParseException {
        JWE jwe = JWEFactory.parse("eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0.H3X6mT5HLgcFfzLoe4ku6Knhh9Ofv1eL.qF5-N_7K8VQ4yMSz.WXUNY6eg5fR4tc8Hqf5XDRM9ALGwcQyYG4IYwwg8Ctkx1UuxoV7t6UnemjzCj2sOYUqi3KYpDzrKVJpzokz0vcIem4lFe5N_ds8FAMpW0GSF9ePA8qvV99WaP0N2ECVPmgihvL6qwNhdptlLKtxcOpE41U5LnU22voPK55VF4_1j0WmTgWgZ7DwLDysp6EIDjrrt-DY.febBmP71KADmKRVfeSnv_g");

        assertThat(jwe.information()).isEmpty();
    }
}