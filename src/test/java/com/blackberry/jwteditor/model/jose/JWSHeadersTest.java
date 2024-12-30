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
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;

class JWSHeadersTest {

    @Test
    void givenJWSWithCompactHeader_thenHeaderIsCompact() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        assertThat(jws.header().isCompact()).isTrue();
    }

    @Test
    void givenJWSWithNonCompactHeader_thenHeaderIsNotCompact() throws ParseException {
        JWS jws = JWSFactory.parse("ewogICAgInR5cCI6ICJKV1QiLAogICAgImFsZyI6ICJub25lIgp9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        assertThat(jws.header().isCompact()).isFalse();
    }

    @Test
    void givenJWSWithCompactHeader_thenPrettyPrintDecodedHeaderIsCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        String decodedHeader = jws.header().decodeAndPrettyPrint();

        assertThat(decodedHeader).isEqualTo("""
                {
                    "typ": "JWT",
                    "alg": "none"
                }""");
    }

    @Test
    void givenJWS_thenDecodedHeaderIsCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        String decodedHeader = jws.header().decoded();

        assertThat(decodedHeader).isEqualTo("{\"typ\":\"JWT\",\"alg\":\"none\"}");
    }

    @Test
    void givenJWS_thenEncodedHeaderIsCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        Base64URL encodedHeader = jws.header().encoded();

        assertThat(encodedHeader).isEqualTo(new Base64URL("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0"));
    }

    @Test
    void givenJWS_thenHeaderJsonIsCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        JSONObject headerJson = jws.header().json();

        assertThat(headerJson.similar(new JSONObject("{\"typ\":\"JWT\",\"alg\":\"none\"}"))).isTrue();
    }

    @Test
    void givenJWS_thenHeaderSerializationCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        String data = jws.header().toString();

        assertThat(data).isEqualTo("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0");
    }
}