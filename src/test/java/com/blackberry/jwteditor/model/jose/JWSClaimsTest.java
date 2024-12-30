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

import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static com.blackberry.jwteditor.model.jose.ClaimsType.JSON;
import static com.blackberry.jwteditor.model.jose.ClaimsType.TEXT;
import static org.assertj.core.api.Assertions.assertThat;

class JWSClaimsTest {

    @Test
    void givenJWSWithJsonClaims_thenClaimsTypeIsCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        JWSClaims claims = jws.claims();

        assertThat(claims.type()).isEqualTo(JSON);
    }

    @Test
    void givenJWSWithJsonClaims_thenDecodedClaimsIsCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        String decodedClaims = jws.claims().decoded();

        assertThat(decodedClaims).isEqualTo("{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}");
    }

    @Test
    void givenJWSWithJsonClaims_thenEncodedClaimsIsCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        Base64URL encodedClaims = jws.claims().encoded();

        assertThat(encodedClaims).isEqualTo(new Base64URL("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9"));
    }

    @Test
    void givenJWSWithJsonClaims_thenClaimsSerializationCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        String data = jws.claims().toString();

        assertThat(data).isEqualTo("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9");
    }

    @Test
    void givenJWSWithTextClaims_thenClaimsTypeIsCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJhbGciOiJSUzI1NiIsImtpZCI6InlmdTlwUzlTaXVDZzNiaXZvZXZuNkxmZEZ2NUlMZk9wT3RsNnRCYmRlemsifQ.dXNlcg.soNtldMC7sxtVPSxkgvd7L7wPZ2FTMRvP-xgOjM5fQ3N74GeZZEKDzjaKeJ10EBeE4OcQkJeyawk5zmra65Nosc3BWDFieA7qUokVvW6qmKKnk7AoeBexirwVurAz4iOsaH5TQ_5Vwou1A2yHZSbuPBdq-Ofat9KKH5mo86yvLrEy2M3ikvOOJ3PFU49jLH9o1uCUCBKo-9g6B22b-q8Xwpt3faPa5RX0P6ihYt0wtsa4VecagLZyjDxfG46xWs7-aWpEi7pymGJdyLcD3ioUE5X6AbIIo7b73xfxLj4yjBjm-WROfPd4n82mh276ZHmEkw2F8eKYcWUp2YdPvZRyA");

        JWSClaims claims = jws.claims();

        assertThat(claims.type()).isEqualTo(TEXT);
    }

    @Test
    void givenJWSWithTextClaims_thenDecodedClaimsIsCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.dXNlcg.");

        String decodedClaims = jws.claims().decoded();

        assertThat(decodedClaims).isEqualTo("user");
    }

    @Test
    void givenJWSWithTextClaims_thenEncodedClaimsIsCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.dXNlcg.");

        Base64URL encodedClaims = jws.claims().encoded();

        assertThat(encodedClaims).isEqualTo(new Base64URL("dXNlcg"));
    }

    @Test
    void givenJWSWithTextClaims_thenClaimsSerializationCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.dXNlcg.");

        String data = jws.claims().toString();

        assertThat(data).isEqualTo("dXNlcg");
    }

    @Test
    void givenJWSWithTextClaims_thenTimesClaimsEmpty() throws ParseException {
        JWS jws = JWSFactory.parse("eyJhbGciOiJSUzI1NiIsImtpZCI6InlmdTlwUzlTaXVDZzNiaXZvZXZuNkxmZEZ2NUlMZk9wT3RsNnRCYmRlemsifQ.dXNlcg.soNtldMC7sxtVPSxkgvd7L7wPZ2FTMRvP-xgOjM5fQ3N74GeZZEKDzjaKeJ10EBeE4OcQkJeyawk5zmra65Nosc3BWDFieA7qUokVvW6qmKKnk7AoeBexirwVurAz4iOsaH5TQ_5Vwou1A2yHZSbuPBdq-Ofat9KKH5mo86yvLrEy2M3ikvOOJ3PFU49jLH9o1uCUCBKo-9g6B22b-q8Xwpt3faPa5RX0P6ihYt0wtsa4VecagLZyjDxfG46xWs7-aWpEi7pymGJdyLcD3ioUE5X6AbIIo7b73xfxLj4yjBjm-WROfPd4n82mh276ZHmEkw2F8eKYcWUp2YdPvZRyA");

        JWSClaims claims = jws.claims();

        assertThat(claims.timeClaims()).isEmpty();
    }
}