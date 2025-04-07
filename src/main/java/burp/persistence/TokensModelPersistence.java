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
import com.blackberry.jwteditor.model.tokens.Token;
import com.blackberry.jwteditor.model.tokens.TokensModel;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

public class TokensModelPersistence {
    static final String TOKEN_JSON_KEY = "tokenList";

    private final boolean isProVersion;
    private final PersistedObject extensionData;

    public TokensModelPersistence(boolean isProVersion, PersistedObject extensionData) {
        this.isProVersion = isProVersion;
        this.extensionData = extensionData;
    }

    public TokensModel loadOrCreateNew() {
        String tokensJson = isProVersion ? extensionData.getString(TOKEN_JSON_KEY) : null;

        if (tokensJson == null || tokensJson.isEmpty()) {
            return new TokensModel();
        }

        List<Token> tokenList = new ArrayList<>();

        try {
            for (Object object : new JSONArray(tokensJson)) {
                Token token = TokenPersistence.deserialize(object);

                if (token != null) {
                    tokenList.add(token);
                }
            }
        } catch (JSONException ignored) {
        }

        return new TokensModel(tokenList);
    }

    public void save(TokensModel tokensModel) {
        if (!isProVersion) {
            return;
        }

        JSONArray tokensArray = new JSONArray();

        tokensModel.tokens().stream()
                .map(TokenPersistence::serialize)
                .map(JSONObject::new)
                .forEach(tokensArray::put);

        extensionData.setString(TOKEN_JSON_KEY, tokensArray.toString());
    }
}
