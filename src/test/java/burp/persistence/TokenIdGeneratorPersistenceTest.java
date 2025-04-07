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
import com.blackberry.jwteditor.model.tokens.TokenIdGenerator;
import org.junit.jupiter.api.Test;

import static burp.persistence.TokensIdGeneratorPersistence.TOKEN_COUNTER_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class TokenIdGeneratorPersistenceTest {
    private final PersistedObject extensionData = mock(PersistedObject.class);

    @Test
    void givenNotProVersion_whenLoadIdGenerator_thenExtensionDataNotCalled() {
        TokensIdGeneratorPersistence persistence = new TokensIdGeneratorPersistence(false, extensionData);

        persistence.loadOrCreateNew();

        verifyNoInteractions(extensionData);
    }

    @Test
    void givenProVersion_whenLoadIdGenerator_thenCorrectDataLoadedFromExtensionData() {
        TokensIdGeneratorPersistence persistence = new TokensIdGeneratorPersistence(true, extensionData);

        persistence.loadOrCreateNew();

        verify(extensionData).getInteger(TOKEN_COUNTER_KEY);
        verifyNoMoreInteractions(extensionData);
    }

    @Test
    void givenNoSavedCounter_whenLoadOrCreateCalled_thenCounterStartsAtOne() {
        when(extensionData.getInteger(TOKEN_COUNTER_KEY)).thenReturn(null);
        TokensIdGeneratorPersistence persistence = new TokensIdGeneratorPersistence(true, extensionData);

        TokenIdGenerator idGenerator = persistence.loadOrCreateNew();

        assertThat(idGenerator).isNotNull();
        assertThat(idGenerator.next()).isOne();
    }

    @Test
    void givenInvalidSavedCounter_whenLoadOrCreateCalled_thenCounterStartsAtOne() {
        when(extensionData.getInteger(TOKEN_COUNTER_KEY)).thenReturn(-1);
        TokensIdGeneratorPersistence persistence = new TokensIdGeneratorPersistence(true, extensionData);

        TokenIdGenerator idGenerator = persistence.loadOrCreateNew();

        assertThat(idGenerator).isNotNull();
        assertThat(idGenerator.next()).isOne();
    }

    @Test
    void givenZeroSavedCounter_whenLoadOrCreateCalled_thenCounterStartsAtOne() {
        when(extensionData.getInteger(TOKEN_COUNTER_KEY)).thenReturn(0);
        TokensIdGeneratorPersistence persistence = new TokensIdGeneratorPersistence(true, extensionData);

        TokenIdGenerator idGenerator = persistence.loadOrCreateNew();

        assertThat(idGenerator).isNotNull();
        assertThat(idGenerator.next()).isOne();
    }

    @Test
    void givenNonZeroSavedCounter_whenLoadOrCreateCalled_thenCounterHasCorrectNextValue() {
        when(extensionData.getInteger(TOKEN_COUNTER_KEY)).thenReturn(447);
        TokensIdGeneratorPersistence persistence = new TokensIdGeneratorPersistence(true, extensionData);

        TokenIdGenerator idGenerator = persistence.loadOrCreateNew();

        assertThat(idGenerator).isNotNull();
        assertThat(idGenerator.next()).isEqualTo(448);
    }

    @Test
    void givenNotProVersion_whenSave_thenExtensionDataNotCalled() {
        TokensIdGeneratorPersistence persistence = new TokensIdGeneratorPersistence(false, extensionData);

        persistence.save(new TokenIdGenerator());

        verifyNoInteractions(extensionData);
    }

    @Test
    void givenUnusedCounter_whenSave_thenZeroLastIdSaved() {
        TokensIdGeneratorPersistence persistence = new TokensIdGeneratorPersistence(true, extensionData);

        persistence.save(new TokenIdGenerator());

        verify(extensionData).setInteger(TOKEN_COUNTER_KEY, 0);
        verifyNoMoreInteractions(extensionData);
    }

    @Test
    void givenUsedCounter_whenSave_thenNonZeroLastIdSaved() {
        TokensIdGeneratorPersistence persistence = new TokensIdGeneratorPersistence(true, extensionData);

        persistence.save(new TokenIdGenerator(448));

        verify(extensionData).setInteger(TOKEN_COUNTER_KEY, 448);
        verifyNoMoreInteractions(extensionData);
    }
}