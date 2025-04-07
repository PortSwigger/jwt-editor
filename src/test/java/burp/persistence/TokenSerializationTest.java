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

import com.blackberry.jwteditor.model.jose.JWSFactory;
import com.blackberry.jwteditor.model.tokens.Token;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.text.ParseException;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class TokenSerializationTest {
    private static Stream<Arguments> data() throws ParseException {
        return Stream.of(
                arguments(
                        new Token(101, "host", "path", JWSFactory.parse("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYW1lIjoiSm9obiBEb2UifQ.")),
                        "{\"id\": 101, \"host\": \"host\", path: \"path\", \"jws\": \"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYW1lIjoiSm9obiBEb2UifQ.\"}"
                ),
                arguments(
                        new Token(99, "jwt.io", "/", JWSFactory.parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImVtYW5vbiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ApPRqkKBdZFBOmQpwKnI7Nv2HR4euszd9ReUU-ZJUvc")),
                        "{\"id\": 99, \"host\": \"jwt.io\", path: \"/\", \"jws\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImVtYW5vbiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ApPRqkKBdZFBOmQpwKnI7Nv2HR4euszd9ReUU-ZJUvc\"}"
                )
        );
    }

    @MethodSource("data")
    @ParameterizedTest
    void givenToken_whenSerialize_thenJsonCorrect(Token token, String expectedJson) {
        String json = TokenPersistence.serialize(token);

        assertThat(json).isEqualToIgnoringWhitespace(expectedJson);
    }
}