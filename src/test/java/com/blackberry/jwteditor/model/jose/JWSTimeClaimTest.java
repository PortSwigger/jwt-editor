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
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.text.ParseException;
import java.util.stream.Stream;

import static com.blackberry.jwteditor.model.jose.TimeClaimType.*;
import static org.assertj.core.api.Assertions.assertThat;

class JWSTimeClaimTest {

    @BeforeAll
    static void setTimeZone() {
        System.setProperty("user.timezone", "UTC");
    }

    @Test
    void givenJWSWithNoTimeClaims_thenTimeClaimsIsEmpty() throws ParseException {
        JWS jws = JWSFactory.parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZXN0In0.WVLalefVZ5Rj991Cjgh0qBjKSIQaqC_CgN3b-30GKpQ");

        assertThat(jws.claims().timeClaims()).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNzE2MjM5MDIyfQ.FuJB22Dq3zXcFXtIAc59tWnmbbFC6jRXzb_2ejbhhoQ",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoiMTcxNjIzOTAyMiJ9.8Tm8e1DEoD92S98fm9Hh_xFMsFVGNN7VjRZppD-bfMM"
    })
    void givenJWSWithExpTimeClaims_thenTimeClaimsCorrect(String data) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        assertThat(jws.claims().timeClaims()).containsExactly(TimeClaimFactory.fromEpochSeconds(EXPIRATION_TIME, "1716239022"));
    }

    private static Stream<String> jwsWithValidExpValues() {
        return Stream.of(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoyMzE2MjM5MDIyfQ.nmCDcUHT-yLgrRG1LKMH9E2FQs2xWcB8CncxoqKdQEQ",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoiMjMxNjIzOTAyMiJ9.kDOLZJTcFVwrSVSDeFK31EIx7Q4e4Ya33iNCk4QZ10c",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoyMzE2MjM5MDIyLjEyMzQ1Nn0.H1-2jQa-px7ubm0npoG1-cWzDWNOh2IDQlsz4-Wwcyk",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoiMjMxNjIzOTAyMi4xMjM0NTYifQ.MST0_jbQJRT5p_HE8jiutwo1UJlno_G57TcizmbCS4k",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoiMjAzNi0xMi0xOVQxNjozOTo1Ny0wODowMCJ9."
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithValidExpValues")
    void givenJWSWithExpTimeClaims_whenExpiryDateInTheFuture_thenTimeClaimValid(String data) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        TimeClaim timeClaim = jws.claims().timeClaims().getFirst();

        assertThat(timeClaim.type()).isEqualTo(EXPIRATION_TIME);
        assertThat(timeClaim.isValid()).isTrue();
    }

    private static Stream<String> jwsWithInvalidExpValues() {
        return Stream.of(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoiemVvbGl0ZSJ9.Vsy0uiJVpA17ys9DRFWldEcgiut_N5QhvHCRRcp8Xow",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjpudWxsfQ.JsGUzIiM3S7cZF3LjYg-S6rYz4VXK-GBpGELzNJKOgY",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjotMTIzNDV9.BCgzT_CEurIxa0MxbS9seJ62lgfJT54P7AQpUkp65GE",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjotMTIzNDUuNjc4OX0.y5y6TxxnzznRjSms67yg9O-U4t_RwV9wBz588gqB99M"
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithInvalidExpValues")
    void givenJWSWithExpTimeClaims_whenExpiryDateInvalid_thenTimeClaimNotValid(String data) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        TimeClaim timeClaim = jws.claims().timeClaims().getFirst();

        assertThat(timeClaim.type()).isEqualTo(EXPIRATION_TIME);
        assertThat(timeClaim.isValid()).isFalse();
    }

    private static Stream<String> jwsWithExpValuesInThePast() {
        return Stream.of(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJleHAiOjE1MTYyMzkwMjJ9.mVGXFv3OuwtuZPsdaf_oGUYm2uOH-T-JRTDQE1c10q0",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJleHAiOjE1MTYyMzkwMjIuMTIzNDU2fQ.Nx2K7VSNCFGSOzLvB4cKyqUJfnYJUekVx3kvctsLYZk",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJleHAiOjB9.eVVhRMapPD77WuMWIHKBqYw0cjJHC49On-mHEuonYjk",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJleHAiOjB9.z4UM0Z_ZONsVCh4Cw9NyNKy3GN9PmBWCvVo6Dw12CiY"
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithExpValuesInThePast")
    void givenJWSWithExpTimeClaims_whenExpiryDateIsInThePast_thenTimeClaimNotValid(String data) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        TimeClaim timeClaim = jws.claims().timeClaims().getFirst();

        assertThat(timeClaim.type()).isEqualTo(EXPIRATION_TIME);
        assertThat(timeClaim.isValid()).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjoxNzE2MjM5MDIyfQ.mZ_wGwRA0BBp_m6LJOPOBfwMosKrhTf9DbnKZYTzBzg",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjoiMTcxNjIzOTAyMiJ9.JD7t6jE6sOzuaFi5Lj5e3RhnoRDDWW9QHv_U3bFgEKM"})
    void givenJWSWithNbfTimeClaims_thenTimeClaimsCorrect(String data) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        assertThat(jws.claims().timeClaims()).containsExactly(TimeClaimFactory.fromEpochSeconds(NOT_BEFORE_TIME, "1716239022"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjoxNzE2MjM5MDIyLjEyMzQ1Nn0.22WbREJsZuvAaRiGNXSENHg0JC81QL5nUxKpWOtVSR8",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjoiMTcxNjIzOTAyMi4xMjM0NTYifQ.B_WI9vnukq93HeQ1xeWqQms4zZU0BAWL9irQdhoGfh0"
    })
    void givenJWSWithNbfTimeClaimsMicroseconds_thenTimeClaimsCorrect(String data) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        assertThat(jws.claims().timeClaims()).containsExactly(TimeClaimFactory.fromEpochSeconds(NOT_BEFORE_TIME, "1716239022.123456"));
    }

    private static Stream<String> jwsWithValidNbfValues() {
        return Stream.of(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjoxNzE2MjM5MDIyfQ.mZ_wGwRA0BBp_m6LJOPOBfwMosKrhTf9DbnKZYTzBzg",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjoiMTcxNjIzOTAyMiJ9.JD7t6jE6sOzuaFi5Lj5e3RhnoRDDWW9QHv_U3bFgEKM",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJuYmYiOjE1MTYyMzkwMjJ9.1OhNEYnVM64dytXGZ1kj_Z3fV73xGFxWyba52S5r7wc",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJuYmYiOjB9.AqIAHlKSdpcDp7mD6sWsfKCQxI2hyJYsI7Y4Dh6N6pI",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJuYmYiOjE3MjIxNjc0Nzd9.2almhOGrigs8lXH9DLKBkkUCS6r5j7zpJXYsXJN39d4",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJuYmYiOjE3MjIxNjc0NzcuMTIzNDU2fQ.Jhjav96AdbK5WDM3yyd48nPZgXs5bU1LNypxc0EiY8g",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJuYmYiOiIxNzIyMTY3NDc3LjEyMzQ1NiJ9.AjRS20zLSXrDUW9YuD7xly_iRkRJb9UyKwd72MpNKf8",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjoiMjAyNC0wNS0yMFQyMjowMzo0MiswMTowMCJ9."
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithValidNbfValues")
    void givenJWSWithNbfTimeClaims_whenNotBeforeDateInThePast_thenTimeClaimValid(String data) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        TimeClaim timeClaim = jws.claims().timeClaims().getFirst();

        assertThat(timeClaim.type()).isEqualTo(NOT_BEFORE_TIME);
        assertThat(timeClaim.isValid()).isTrue();
    }

    private static Stream<String> jwsWithInvalidNbfValues() {
        return Stream.of(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjoiemVvbGl0ZSJ9.kmx4FteQrcATfc2Zx47WypsqrIC-e1IM4opeLJxLyrI",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjpudWxsfQ.Nyai4iIAzjR5OcUwaE8xQYbArYuBIzbKxaJDnvu1J_I",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjotMTIzNDV9.rlnrK7unNEaaghPFhNQnDp1GRbCU0rGORO2yDf5YIZk",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjotMTIzNDUuNjc4OX0.bXoLasbuZk8NZNyYj3HCNIIvXGUb96ffvfveXwHIX4g"
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithInvalidNbfValues")
    void givenJWSWithNbfTimeClaims_whenNotBeforeDateInvalid_thenTimeClaimNotValid(String data) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        TimeClaim timeClaim = jws.claims().timeClaims().getFirst();

        assertThat(timeClaim.type()).isEqualTo(NOT_BEFORE_TIME);
        assertThat(timeClaim.isValid()).isFalse();
    }
    private static Stream<String> jwsWithFutureNbfValues() {
        return Stream.of(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJuYmYiOjIzMjIxNjc0Nzd9.cMocfo6ghvuYBqDwZ9GBdfbCnMLsUcZe2GZRuaah0-c",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJuYmYiOjE4MjIxNjc0Nzd9._m-Rhio9DLcVRfWo7S-KIvlTk29QuDgal-tqreN4y4E",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJuYmYiOjIzMjIxNjc0NzcuMTIzNDU2fQ.VC7D0b27ETWQMuxbWsLdmHfPvIbwadH5qQHCoP7o_g0"
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithFutureNbfValues")
    void givenJWSWithNbfTimeClaims_whenNotBeforeDateIsInTheFuture_thenTimeClaimNotValid(String data) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        TimeClaim timeClaim = jws.claims().timeClaims().getFirst();

        assertThat(timeClaim.type()).isEqualTo(NOT_BEFORE_TIME);
        assertThat(timeClaim.isValid()).isFalse();
    }

    private static Stream<String> jwsWithValidIatValues() {
        return Stream.of(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE3MTYyMzkwMjJ9.y06rqsXv0DMutukwDaUJU0Sf-Ye3qrDkyFpOaj1J08A",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOiIxNzE2MjM5MDIyIn0.c2Ogr8QeTwopupVPqI56VaovZXE3svug2BI-Trft2EA"
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithValidIatValues")
    void givenJWSWithIatTimeClaims_thenTimeClaimsCorrect(String data) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        assertThat(jws.claims().timeClaims()).containsExactly(TimeClaimFactory.fromEpochSeconds(ISSUED_AT_TIME, "1716239022"));
    }

    private static Stream<String> jwsWithValidIatValuesMicroseconds() {
        return Stream.of(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE3MTYyMzkwMjIuMTIzNDU2fQ.UinUyun2D9gvOzWrY4cUfSwxB7RhisK3et9x-9PyDC4",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOiIxNzE2MjM5MDIyLjEyMzQ1NiJ9.qNgTvt_NlseJDTQ06s3JIAh2NPSwzrUQ8VM3-iJ94Eg"
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithValidIatValuesMicroseconds")
    void givenJWSWithIatTimeClaimsMicroseconds_thenTimeClaimsCorrect(String data) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        assertThat(jws.claims().timeClaims()).containsExactly(TimeClaimFactory.fromEpochSeconds(ISSUED_AT_TIME, "1716239022.123456"));
    }

    private static Stream<String> jwsWithValidIatDatesInThePast() {
        return Stream.of(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE3MTYyMzkwMjJ9.y06rqsXv0DMutukwDaUJU0Sf-Ye3qrDkyFpOaj1J08A",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOiIxNzE2MjM5MDIyIn0.c2Ogr8QeTwopupVPqI56VaovZXE3svug2BI-Trft2EA",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.hqWGSaFpvbrXkOWc6lrnffhNWR19W_S1YKFBx2arWBk",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjB9.9TaucSjKgR3_gXUlzTGperv3PK9IAXO0ZVbgP9Wx4IY",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE3MjIxNjc0Nzd9.SWmvLUBWE5ddBWvSEWnrHM8W3rfzyYmEQVk6-ywFFgQ",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE3MjIxNjc0NzcuMTIzNDU2fQ.iamH_Bs-iyDuqJXD4Rs49oDupZTT7JWqgMQRqJqFoMQ",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOiIxNzIyMTY3NDc3LjEyMzQ1NiJ9.C4Z6HY5SPvHyxgUFHA3eBzOPaXoLUzY6uRReHhnSz1I",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoiMjAyNC0wNS0yMFQyMjowMzo0MiswMTowMCJ9."
        );
    }

    @ParameterizedTest
    @MethodSource("jwsWithValidIatDatesInThePast")
    void givenJWSWithIatTimeClaims_whenIssuedAtDateInThePast_thenTimeClaimValid(String data) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        TimeClaim timeClaim = jws.claims().timeClaims().getFirst();

        assertThat(timeClaim.type()).isEqualTo(ISSUED_AT_TIME);
        assertThat(timeClaim.isValid()).isTrue();
    }

    private static Stream<String> jwsWithInvalidIatValues() {
        return Stream.of(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOiJ6ZW9saXRlIn0.-IpgDK_M_jQJQ6FDa-wd25xGFJ2bHNthdYn1JlQNxjg",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOm51bGx9.uplfi-hImBCsHTs__K-0LU612y3EW92J1TbINlDGc-k",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOi0xMjM0NX0.gVkVHyEasqw2NZ63un0T9Yd6bW8bmY9uMYndlptiQzQ",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOi0xMjM0NS42Nzg5fQ.kWOjxuK9euJp7rcgG4WcaXuEwjk2goaVrIEdS_lmwnU"
                );
    }

    @ParameterizedTest
    @MethodSource("jwsWithInvalidIatValues")
    void givenJWSWithIatTimeClaims_whenIssuedAtDateInvalid_thenTimeClaimNotValid(String data) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        TimeClaim timeClaim = jws.claims().timeClaims().getFirst();

        assertThat(timeClaim.type()).isEqualTo(ISSUED_AT_TIME);
        assertThat(timeClaim.isValid()).isFalse();
    }

    private static Stream<String> jwsWithFutureIatDates() {
        return Stream.of(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjIzMjIxNjc0Nzd9.3UYGoLpdXRhnlai81VFV_iWmW90xnCimcYverY1-Zk4",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE4MjIxNjc0Nzd9._H-G7WjMbg8IVADVbz1Lsd7I_bGQZBYKPf8S2Q9vxf4",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjIzMjIxNjc0NzcuMTIzNDU2fQ.7ue0C6Wo06Hb_HoVHnQ7eMUPkQFN_Q6YyyNzqVQ8Qq8"
        );
    }
    @ParameterizedTest
    @MethodSource("jwsWithFutureIatDates")
    void givenJWSWithIatTimeClaims_whenIssuedAtDateIsInTheFuture_thenTimeClaimNotValid(String data) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        TimeClaim timeClaim = jws.claims().timeClaims().getFirst();

        assertThat(timeClaim.type()).isEqualTo(ISSUED_AT_TIME);
        assertThat(timeClaim.isValid()).isFalse();
    }
}