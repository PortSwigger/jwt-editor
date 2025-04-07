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

import burp.api.montoya.persistence.PersistedObject;
import com.blackberry.jwteditor.model.jose.JWSFactory;
import com.blackberry.jwteditor.model.tokens.Token;
import com.blackberry.jwteditor.model.tokens.TokensModel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.text.ParseException;
import java.util.stream.Stream;

import static burp.persistence.TokensModelPersistence.TOKEN_JSON_KEY;
import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class TokensModelPersistenceTest {
    private final PersistedObject extensionData = mock(PersistedObject.class);

    @Test
    void givenNotProVersion_whenLoadTokensModel_thenExtensionDataNotCalled() {
        TokensModelPersistence tokensPersistence = new TokensModelPersistence(false, extensionData);

        tokensPersistence.loadOrCreateNew();

        verifyNoInteractions(extensionData);
    }

    @Test
    void givenProVersion_whenLoadTokensModel_thenCorrectDataLoadedFromExtensionData() {
        TokensModelPersistence tokensPersistence = new TokensModelPersistence(true, extensionData);

        tokensPersistence.loadOrCreateNew();

        verify(extensionData).getString(TOKEN_JSON_KEY);
        verifyNoMoreInteractions(extensionData);
    }

    @Test
    void givenNoSavedTokens_whenLoadOrCreateCalled_thenEmptyModelReturned() {
        TokensModelPersistence tokensPersistence = new TokensModelPersistence(true, extensionData);

        TokensModel tokensModel = tokensPersistence.loadOrCreateNew();

        assertThat(tokensModel).isNotNull();
        assertThat(tokensModel.tokens()).isEmpty();
    }

    private static Stream<String> invalidConfigJson() {
        return Stream.of(
                "",
                "{",
                "]",
                "[",
                "true",
                "{}",
                "null",
                "448",
                "\"Edwards\""
        );
    }

    @ParameterizedTest
    @MethodSource("invalidConfigJson")
    void givenInvalidSavedTokens_whenLoadOrCreateCalled_thenEmptyModelReturned(String invalidJson) {
        when(extensionData.getString(TOKEN_JSON_KEY)).thenReturn(invalidJson);
        TokensModelPersistence tokensPersistence = new TokensModelPersistence(true, extensionData);

        TokensModel tokensModel = tokensPersistence.loadOrCreateNew();

        assertThat(tokensModel).isNotNull();
        assertThat(tokensModel.tokens()).isEmpty();
    }

    @Test
    void givenEmptySavedTokens_whenLoadOrCreateCalled_thenEmptyModelReturned() {
        when(extensionData.getString(TOKEN_JSON_KEY)).thenReturn("");
        TokensModelPersistence tokensPersistence = new TokensModelPersistence(true, extensionData);

        TokensModel tokensModel = tokensPersistence.loadOrCreateNew();

        assertThat(tokensModel).isNotNull();
        assertThat(tokensModel.tokens()).isEmpty();
    }

    @Test
    void givenEmptyListSavedTokens_whenLoadOrCreateCalled_thenEmptyModelReturned() {
        when(extensionData.getString(TOKEN_JSON_KEY)).thenReturn("[]");
        TokensModelPersistence tokensPersistence = new TokensModelPersistence(true, extensionData);

        TokensModel tokensModel = tokensPersistence.loadOrCreateNew();

        assertThat(tokensModel).isNotNull();
        assertThat(tokensModel.tokens()).isEmpty();
    }

    @Test
    void givenValidSavedTokens_whenLoadOrCreateCalled_thenNonEmptyModelReturned() {
        when(extensionData.getString(TOKEN_JSON_KEY)).thenReturn("""
                [
                    {"id": 1, "host": "host1", "path": "path1", "jws": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYW1lIjoiSm9obiBEb2UifQ."},
                    {"id": 2, "host": "host2", "path": "path2", "jws": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImVtYW5vbiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ApPRqkKBdZFBOmQpwKnI7Nv2HR4euszd9ReUU-ZJUvc"},
                ]
                """);
        TokensModelPersistence tokensPersistence = new TokensModelPersistence(true, extensionData);

        TokensModel tokensModel = tokensPersistence.loadOrCreateNew();

        assertThat(tokensModel).isNotNull();
        assertThat(tokensModel.tokens()).hasSize(2);
    }

    @Test
    void givenNotProVersion_whenSaveTokensModel_thenExtensionDataNotCalled() {
        TokensModelPersistence tokensPersistence = new TokensModelPersistence(false, extensionData);

        tokensPersistence.save(new TokensModel());

        verifyNoInteractions(extensionData);
    }

    @Test
    void givenEmptyModel_whenSaveTokensModel_thenEmptyListSaved() {
        TokensModelPersistence tokensPersistence = new TokensModelPersistence(true, extensionData);

        tokensPersistence.save(new TokensModel());

        verify(extensionData).setString(TOKEN_JSON_KEY, "[]");
        verifyNoMoreInteractions(extensionData);
    }

    @Test
    void givenNonEmptyModel_whenSaveTokensModel_thenNonEmptyListSaved() throws ParseException {
        TokensModel model = new TokensModel(
                asList(
                        new Token(99, "jwt.io", "/", JWSFactory.parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImVtYW5vbiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ApPRqkKBdZFBOmQpwKnI7Nv2HR4euszd9ReUU-ZJUvc")),
                        new Token(101, "host", "path", JWSFactory.parse("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYW1lIjoiSm9obiBEb2UifQ."))
                )
        );
        TokensModelPersistence tokensPersistence = new TokensModelPersistence(true, extensionData);

        tokensPersistence.save(model);

        verify(extensionData).setString(TOKEN_JSON_KEY, "[{\"path\":\"/\",\"jws\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImVtYW5vbiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ApPRqkKBdZFBOmQpwKnI7Nv2HR4euszd9ReUU-ZJUvc\",\"host\":\"jwt.io\",\"id\":99},{\"path\":\"path\",\"jws\":\"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYW1lIjoiSm9obiBEb2UifQ.\",\"host\":\"host\",\"id\":101}]");
        verifyNoMoreInteractions(extensionData);
    }
}