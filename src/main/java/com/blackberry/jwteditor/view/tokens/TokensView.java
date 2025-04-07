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

package com.blackberry.jwteditor.view.tokens;

import com.blackberry.jwteditor.model.tokens.Token;
import com.blackberry.jwteditor.model.tokens.TokensModel;
import com.blackberry.jwteditor.view.rsta.RstaFactory;
import com.blackberry.jwteditor.view.utils.RunEDTActionOnFirstRenderHierarchyListener;
import com.blackberry.jwteditor.view.utils.table.PercentageBasedColumnWidthTable;
import com.blackberry.jwteditor.view.utils.table.RowHeightDecoratingTableCellRenderer;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableModel;

import static com.blackberry.jwteditor.view.tokens.TokensTableColumnConfiguration.TokensTableColumns.columnWidthPercentages;
import static javax.swing.ListSelectionModel.SINGLE_SELECTION;

public class TokensView {

    private final RstaFactory rstaFactory;

    private JPanel panel;
    private JTable tokenTable;
    private RSyntaxTextArea textAreaPayload;
    private JSplitPane splitPane;

    public TokensView(TokensModel tokensModel, RstaFactory rstaFactory) {
        this.rstaFactory = rstaFactory;

        panel.addHierarchyListener(new RunEDTActionOnFirstRenderHierarchyListener(
                panel,
                () -> splitPane.setDividerLocation(0.5)
        ));

        TableModel tokensTableModel = new TokensTableModel(tokensModel.tokens(), tokensModel::addTokensModelListener);
        tokenTable.setModel(tokensTableModel);

        ListSelectionModel selectionModel = tokenTable.getSelectionModel();
        selectionModel.setSelectionMode(SINGLE_SELECTION);
        selectionModel.addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }

            Token token = tokensModel.tokens().get(selectionModel.getMinSelectionIndex());
            textAreaPayload.setText(token.claims());
        });

        textAreaPayload.setEditable(false);
    }

    private void createUIComponents() {
        textAreaPayload = rstaFactory.buildDefaultTextArea();
        tokenTable = new PercentageBasedColumnWidthTable(columnWidthPercentages());

        TableCellRenderer stringCellRender = tokenTable.getDefaultRenderer(String.class);
        tokenTable.setDefaultRenderer(String.class, new RowHeightDecoratingTableCellRenderer(stringCellRender));
    }
}
