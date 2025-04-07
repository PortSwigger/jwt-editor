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

package burp.persistence;

import com.blackberry.jwteditor.model.tokens.Token;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TokenDeserializationTest {

    @Test
    void givenNonJsonObject_whenDeserialize_thenNullReturned() {
        Token token = TokenPersistence.deserialize("");

        assertThat(token).isNull();
    }

    @Test
    void givenEmptyJsonObject_whenDeserialize_thenNullReturned() {
        Token token = TokenPersistence.deserialize(new JSONObject());

        assertThat(token).isNull();
    }

    @Test
    void givenJsonObjectWithNoId_whenDeserialize_thenNullReturned() {
        String json = "{\"host\": \"host\", path: \"path\", \"jws\": \"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYW1lIjoiSm9obiBEb2UifQ.\"}";

        Token token = TokenPersistence.deserialize(new JSONObject(json));

        assertThat(token).isNull();
    }

    @Test
    void givenJsonObjectWithNegativeId_whenDeserialize_thenNullReturned() {
        String json = "{\"id\": -1, \"host\": \"host\", path: \"path\", \"jws\": \"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYW1lIjoiSm9obiBEb2UifQ.\"}";

        Token token = TokenPersistence.deserialize(new JSONObject(json));

        assertThat(token).isNull();
    }

    @Test
    void givenJsonObjectWithZeroId_whenDeserialize_thenNullReturned() {
        String json = "{\"id\": 0, \"host\": \"host\", path: \"path\", \"jws\": \"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYW1lIjoiSm9obiBEb2UifQ.\"}";

        Token token = TokenPersistence.deserialize(new JSONObject(json));

        assertThat(token).isNull();
    }

    @Test
    void givenJsonObjectWithNoHost_whenDeserialize_thenNullReturned() {
        String json = "{\"id\": 101, path: \"path\", \"jws\": \"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYW1lIjoiSm9obiBEb2UifQ.\"}";

        Token token = TokenPersistence.deserialize(new JSONObject(json));

        assertThat(token).isNull();
    }

    @Test
    void givenJsonObjectWithNoPath_whenDeserialize_thenNullReturned() {
        String json = "{\"id\": 101, \"host\": \"host\", \"jws\": \"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYW1lIjoiSm9obiBEb2UifQ.\"}";

        Token token = TokenPersistence.deserialize(new JSONObject(json));

        assertThat(token).isNull();
    }

    @Test
    void givenJsonObjectWithNoJws_whenDeserialize_thenNullReturned() {
        String json = "{\"id\": 101, \"host\": \"host\", path: \"path\"}";

        Token token = TokenPersistence.deserialize(new JSONObject(json));

        assertThat(token).isNull();
    }

    @Test
    void givenJsonObjectWithInvalidJws_whenDeserialize_thenNullReturned() {
        String json = "{\"id\": 101, \"host\": \"host\", path: \"path\", \"jws\": \"invalid\"}";

        Token token = TokenPersistence.deserialize(new JSONObject(json));

        assertThat(token).isNull();
    }

    @Test
    void givenJsonObjectWithJwsThatIsJwe_whenDeserialize_thenNullReturned() {
        String json = "{\"id\": 101, \"host\": \"host\", path: \"path\", \"jws\": \"eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0..FofRkmAUlKShyhYp.1AjXmQsKwV36LSxZ5YJq7xPPTTUS_e9FyLbd-CWdX72ESWMttHm2xGDWUl-Sp9grmcINWLNwsKezYnJVncfir2o9Uq9vcXENIypU2Qwmymn5q5gJwkR4Wx_RLae9Zm8xP76LJFQe8FssUVHx65Zzvd1I6GbV6FjfbkLF1Z_Ka-olubtWCilFDjIVN7WRUAxmV8syJaM.P0XjuL8_8nK50paY09mB6g\"}";

        Token token = TokenPersistence.deserialize(new JSONObject(json));

        assertThat(token).isNull();
    }

    @Test
    void givenValidJsonObject_whenDeserialize_thenTokenReturned() {
        String json = "{\"id\": 101, \"host\": \"host\", path: \"path\", \"jws\": \"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYW1lIjoiSm9obiBEb2UifQ.\"}";

        Token token = TokenPersistence.deserialize(new JSONObject(json));

        assertThat(token).isNotNull();
        assertThat(token.id()).isEqualTo(101);
        assertThat(token.host()).isEqualTo("host");
        assertThat(token.path()).isEqualTo("path");
        assertThat(token.algorithm()).isEqualTo("none");
        assertThat(token.keyId()).isEqualTo("");
        assertThat(token.claims()).isEqualToIgnoringWhitespace("{\"name\": \"John Doe\"}");
    }
}