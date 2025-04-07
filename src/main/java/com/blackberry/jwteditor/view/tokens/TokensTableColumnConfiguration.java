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

import com.blackberry.jwteditor.utils.Utils;
import com.blackberry.jwteditor.view.utils.table.TableColumnConfiguration;

import static java.util.Arrays.stream;

public class TokensTableColumnConfiguration implements TableColumnConfiguration {

    enum TokensTableColumns {
        ID("id", 5, String.class),
        HOST("host", 35, String.class),
        PATH("path", 35, String.class),
        ALGORITHM("algorithm", 5, String.class),
        KEY_ID("key_id", 20, String.class);

        private final String label;
        private final int widthPercentage;
        private final Class<?> type;

        TokensTableColumns(String labelResourceId, int widthPercentage, Class<?> type) {
            this.label = Utils.getResourceString(labelResourceId);
            this.widthPercentage = widthPercentage;
            this.type = type;
        }

        static int[] columnWidthPercentages() {
            return stream(values()).mapToInt(c -> c.widthPercentage).toArray();
        }

        static TokensTableColumns fromIndex(int index) {
            return values()[index];
        }
    }

    @Override
    public int columnCount() {
        return TokensTableColumns.values().length;
    }

    @Override
    public String columnName(int columnIndex) {
        return TokensTableColumns.values()[columnIndex].label;
    }

    @Override
    public Class<?> columnClass(int columnIndex) {
        return TokensTableColumns.values()[columnIndex].type;
    }
}
