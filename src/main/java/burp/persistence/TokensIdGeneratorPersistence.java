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

public class TokensIdGeneratorPersistence {
    static final String TOKEN_COUNTER_KEY = "tokenIdCounter";

    private final boolean isProVersion;
    private final PersistedObject extensionData;

    public TokensIdGeneratorPersistence(boolean isProVersion, PersistedObject extensionData) {
        this.isProVersion = isProVersion;
        this.extensionData = extensionData;
    }

    public TokenIdGenerator loadOrCreateNew() {
        Integer lastId = isProVersion ? extensionData.getInteger(TOKEN_COUNTER_KEY) : null;

        if (lastId == null || lastId < 0) {
            lastId = 0;
        }

        return new TokenIdGenerator(lastId);
    }

    public void save(TokenIdGenerator idGenerator) {
        if (!isProVersion) {
            return;
        }

        extensionData.setInteger(TOKEN_COUNTER_KEY, idGenerator.next() - 1);
    }
}
