/*
Author : Fraser Winterborn

Copyright 2021 BlackBerry Limited

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
import com.blackberry.jwteditor.model.keys.KeysModel;
import com.blackberry.jwteditor.model.persistence.KeysModelPersistence;
import com.blackberry.jwteditor.presenter.KeysPresenter;
import com.blackberry.jwteditor.presenter.PresenterStore;
import com.blackberry.jwteditor.utils.Utils;
import com.blackberry.jwteditor.view.rsta.RstaFactory;
import com.blackberry.jwteditor.view.utils.AlternateRowBackgroundDecoratingTableCellRenderer;
import com.blackberry.jwteditor.view.utils.PercentageBasedColumnWidthTable;
import com.blackberry.jwteditor.view.utils.RowHeightDecoratingTableCellRenderer;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import static com.blackberry.jwteditor.view.keys.KeysTableColumns.columnWidthPercentages;

/**
 * View class for the Keys tab
 */
public class KeysView {
    private final KeysPresenter presenter;
    private final Window parent;
    private final KeysTableModel keysTableModel;

    private JButton buttonNewSymmetric;
    private JButton buttonNewRSA;
    private JButton buttonNewEC;
    private JButton buttonNewPassword;
    @SuppressWarnings("unused")
    private JPanel panel;
    private JButton buttonNewOKP;
    private JTable tableKeys;

    private JMenuItem menuItemDelete;
    private JMenuItem menuItemCopyJWK;
    private JMenuItem menuItemCopyPEM;
    private JMenuItem menuItemCopyPublicJWK;
    private JMenuItem menuItemCopyPublicPEM;
    private JMenuItem menuItemCopyPassword;
    private JMenuItem menuItemCopyJWKSet;

    public KeysView(
            Window parent,
            PresenterStore presenters,
            KeysModelPersistence keysModelPersistence,
            KeysModel keysModel,
            RstaFactory rstaFactory) {
        this.parent = parent;

        keysTableModel = new KeysTableModel(keysModel.keys());
        tableKeys.setModel(keysTableModel);

        // Initialise the presenter
        presenter = new KeysPresenter(
                this,
                presenters,
                keysModelPersistence,
                keysModel,
                rstaFactory
        );

        // Attach event handlers for button clicks
        buttonNewSymmetric.addActionListener(e -> presenter.onButtonNewSymmetricClick());
        buttonNewEC.addActionListener(e -> presenter.onButtonNewECClick());
        buttonNewOKP.addActionListener(e -> presenter.onButtonNewOKPClick());
        buttonNewRSA.addActionListener(e -> presenter.onButtonNewRSAClick());
        buttonNewPassword.addActionListener(e -> presenter.onButtonNewPasswordClick());
    }

    /**
     * Class for the right-click popup menu
     */
    private class JTablePopup extends PercentageBasedColumnWidthTable {
        private Integer popupRow;

        public JTablePopup() {
            super(columnWidthPercentages());
        }

        @Override
        public JPopupMenu getComponentPopupMenu() {
            // Get the row that has been right-clicked on
            Point p = getMousePosition();

            if (p == null || rowAtPoint(p) < 0) {
                popupRow = null;
                return null;
            }

            popupRow = rowAtPoint(p);

            boolean copyJWKEnabled = false;
            boolean copyPEMEnabled = false;
            boolean copyPublicJWKEnabled = false;
            boolean copyPublicPEMEnabled = false;
            boolean copyPasswordEnabled = false;
            boolean copyJWKKeySet = false;

            // No selection, set the selection
            if (tableKeys.getSelectedRowCount() == 0) {
                tableKeys.changeSelection(popupRow, 0, false, false);
            }
            // Selection equals right-clicked row - this will trigger on right-click release
            else if(tableKeys.getSelectedRowCount() == 1 && tableKeys.getSelectedRow() == popupRow){
                copyJWKEnabled = presenter.canCopyJWK(popupRow);
                copyPEMEnabled = presenter.canCopyPEM(popupRow);
                copyPublicJWKEnabled = presenter.canCopyPublicJWK(popupRow);
                copyPublicPEMEnabled = presenter.canCopyPublicPEM(popupRow);
                copyPasswordEnabled = presenter.canCopyPassword(popupRow);
                copyJWKKeySet = presenter.canCopyJWKSet(new int[]{popupRow});
            }
            // Selection doesn't equal right-clicked row, change the selection
            else if(tableKeys.getSelectedRowCount() == 1 && tableKeys.getSelectedRow() != popupRow) {
                tableKeys.changeSelection(popupRow, 0, false, false);
            } else {
                copyJWKKeySet = presenter.canCopyJWKSet(tableKeys.getSelectedRows());
            }

            menuItemCopyJWK.setEnabled(copyJWKEnabled);
            menuItemCopyPEM.setEnabled(copyPEMEnabled);
            menuItemCopyPublicJWK.setEnabled(copyPublicJWKEnabled);
            menuItemCopyPublicPEM.setEnabled(copyPublicPEMEnabled);
            menuItemCopyPassword.setEnabled(copyPasswordEnabled);
            menuItemCopyJWKSet.setEnabled(copyJWKKeySet);

            return super.getComponentPopupMenu();
        }

        public Integer getPopupRow(){
            return popupRow;
        }
    }

    /**
     * Get the currently selected row of the table
     * @return selected row index
     */
    public int getSelectedRow() {
        return tableKeys.getSelectedRow();
    }

    /**
     * Custom form initialisation
     */
    private void createUIComponents() {
        tableKeys = new JTablePopup();

        // Add a handler for double-click events
        tableKeys.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent mouseEvent) {
                // Detect double-clicks and pass the event to the presenter
                if(mouseEvent.getButton() == 1 && mouseEvent.getClickCount() == 2){
                    presenter.onTableKeysDoubleClick();
                }
            }
        });

        // Decorate existing BooleanRenderer to perform alternateRow highlighting
        TableCellRenderer booleanCellRender = tableKeys.getDefaultRenderer(Boolean.class);
        tableKeys.setDefaultRenderer(Boolean.class, new AlternateRowBackgroundDecoratingTableCellRenderer(booleanCellRender));

        // Decorate existing renderer to add additional row height
        TableCellRenderer stringCellRender = tableKeys.getDefaultRenderer(String.class);
        tableKeys.setDefaultRenderer(String.class, new RowHeightDecoratingTableCellRenderer(stringCellRender));

        // Create the right-click menu
        JPopupMenu popupMenu = new JPopupMenu();

        menuItemDelete = new JMenuItem(Utils.getResourceString("delete"));
        menuItemCopyJWK = new JMenuItem(Utils.getResourceString("keys_menu_copy_jwk"));
        menuItemCopyPEM = new JMenuItem(Utils.getResourceString("keys_menu_copy_pem"));
        menuItemCopyPublicJWK = new JMenuItem(Utils.getResourceString("keys_menu_copy_public_jwk"));
        menuItemCopyPublicPEM = new JMenuItem(Utils.getResourceString("keys_menu_copy_public_pem"));
        menuItemCopyPassword = new JMenuItem(Utils.getResourceString("keys_menu_copy_password"));
        menuItemCopyJWKSet = new JMenuItem(Utils.getResourceString("keys_menu_jwk_set"));

        // Event handlers that call the presenter for menu item clicks on the right-click menu
        ActionListener popupMenuActionListener = e -> {
            JMenuItem menuItem = (JMenuItem) e.getSource();
            if (menuItem == menuItemDelete) {
                presenter.onPopupDelete(tableKeys.getSelectedRows());
            } else if (menuItem == menuItemCopyJWK) {
                presenter.onPopupCopyJWK(((JTablePopup) tableKeys).getPopupRow());
            } else if (menuItem == menuItemCopyPEM) {
                presenter.onPopupCopyPEM(((JTablePopup) tableKeys).getPopupRow());
            } else if (menuItem == menuItemCopyPublicJWK) {
                presenter.onPopupCopyPublicJWK(((JTablePopup) tableKeys).getPopupRow());
            } else if (menuItem == menuItemCopyPublicPEM) {
                presenter.onPopupCopyPublicPEM(((JTablePopup) tableKeys).getPopupRow());
            } else if (menuItem == menuItemCopyPassword) {
                presenter.onPopupCopyPassword(((JTablePopup) tableKeys).getPopupRow());
            } else if (menuItem == menuItemCopyJWKSet) {
                presenter.onPopupJWKSet(tableKeys.getSelectedRows());
            }
        };

        // Attach the event handler to the right-click menu buttons
        menuItemDelete.addActionListener(popupMenuActionListener);
        menuItemCopyJWK.addActionListener(popupMenuActionListener);
        menuItemCopyPEM.addActionListener(popupMenuActionListener);
        menuItemCopyPublicJWK.addActionListener(popupMenuActionListener);
        menuItemCopyPublicPEM.addActionListener(popupMenuActionListener);
        menuItemCopyPassword.addActionListener(popupMenuActionListener);
        menuItemCopyJWKSet.addActionListener(popupMenuActionListener);

        // Add the buttons to the right-click menu
        popupMenu.add(menuItemDelete);
        popupMenu.add(menuItemCopyJWK);
        popupMenu.add(menuItemCopyPEM);
        popupMenu.add(menuItemCopyPublicJWK);
        popupMenu.add(menuItemCopyPublicPEM);
        popupMenu.add(menuItemCopyPassword);
        popupMenu.add(menuItemCopyJWKSet);

        // Associate the right-click menu to the table
        tableKeys.setComponentPopupMenu(popupMenu);
    }

    public void addKey(Key key) {
        keysTableModel.addKey(key);
    }

    public void deleteKey(int rowIndex) {
        keysTableModel.deleteRow(rowIndex);
    }

    public void deleteKey(Key key) {
        keysTableModel.deleteKey(key);
    }

    public Window getParent() {
        return parent;
    }
}
