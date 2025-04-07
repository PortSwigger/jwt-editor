/*
Author : Dolph Flynn

Copyright 2023 Dolph Flynn

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

package com.blackberry.jwteditor.view.tokens;

import com.blackberry.jwteditor.model.tokens.Token;
import com.blackberry.jwteditor.model.tokens.TokensModelListener;
import com.blackberry.jwteditor.view.tokens.TokensTableColumnConfiguration.TokensTableColumns;
import com.blackberry.jwteditor.view.utils.table.GenericTableModel;

import java.util.List;
import java.util.function.Consumer;

class TokensTableModel extends GenericTableModel {
    private final List<Token> tokens;

    TokensTableModel(List<Token> tokens, Consumer<TokensModelListener> listenerConsumer) {
        super(new TokensTableColumnConfiguration());

        this.tokens = tokens;

        listenerConsumer.accept(new TokensModelListener() {
            @Override
            public void notifyTokenInserted(Token token) {
                fireTableRowsInserted(tokens.size() - 1, tokens.size() - 1);
            }

            @Override
            public void notifyTokenDeleted(int index) {
                fireTableRowsDeleted(index, index);
            }
        });
    }

    @Override
    public int getRowCount() {
        return tokens.size();
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= tokens.size()) {
            return null;
        }

        Token token = tokens.get(rowIndex);
        TokensTableColumns column = TokensTableColumns.fromIndex(columnIndex);

        return switch (column) {
            case ID -> token.id();
            case HOST -> token.host();
            case PATH -> token.path();
            case ALGORITHM -> token.algorithm();
            case KEY_ID -> token.keyId();
        };
    }
}
