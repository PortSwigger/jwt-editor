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

package com.blackberry.jwteditor.view.keys;

import com.blackberry.jwteditor.model.keys.Key;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Model for the keys table
 */
class KeysTableModel extends AbstractTableModel {
    private final List<Key> data;

    KeysTableModel(Iterable<Key> keys) {
        this.data = new ArrayList<>();
        keys.forEach(data::add);
    }

    void addKey(Key key) {
        int nextRowIndex = data.size();
        data.add(key);
        fireTableRowsInserted(nextRowIndex, nextRowIndex);
    }

    void deleteKey(Key key) {
        int index = data.indexOf(key);
        deleteRow(index);
    }

    void deleteRow(int rowIndex) {
        data.remove(rowIndex);
        fireTableRowsDeleted(rowIndex, rowIndex);
    }

    @Override
    public int getRowCount() {
        return data.size();
    }

    @Override
    public int getColumnCount() {
        return KeysTableColumns.values().length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= data.size()) {
            return null;
        }

        Key key = data.get(rowIndex);
        KeysTableColumns column = KeysTableColumns.fromIndex(columnIndex);

        return switch (column) {
            case ID -> key.getID();
            case TYPE -> key.getDescription();
            case PUBLIC_KEY -> key.isPublic();
            case PRIVATE_KEY -> key.isPrivate();
            case SIGNING -> key.canSign();
            case VERIFICATION -> key.canVerify();
            case ENCRYPTION -> key.canEncrypt();
            case DECRYPTION -> key.canDecrypt();
        };
    }

    @Override
    public String getColumnName(int column) {
        return KeysTableColumns.labelWithIndex(column);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return KeysTableColumns.typeForIndex(columnIndex);
    }
}
