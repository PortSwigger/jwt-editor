/*
Author : Dolph Flynn

Copyright 2022 Dolph Flynn

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

package com.blackberry.jwteditor.view.dialog.config;

import burp.config.BurpConfig;
import burp.intruder.FuzzLocation;
import burp.intruder.IntruderConfig;
import burp.proxy.HighlightColor;
import burp.proxy.ProxyConfig;
import com.blackberry.jwteditor.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/**
 *  Dialog for Burp proxy config
 */
public class BurpConfigDialog extends JDialog {
    private final BurpConfig burpConfig;

    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JCheckBox checkBoxHighlightJWT;
    private JLabel labelHighlightColor;
    private JComboBox comboBoxHighlightColor;
    private JLabel labelHighlightJWT;
    private JTextField intruderParameterName;
    private JComboBox comboBoxPayloadPosition;

    /**
     * Creates new ProxyConfigDialog
     *
     * @param parent parent window
     * @param burpConfig burp config instance
     */
    public BurpConfigDialog(Window parent, BurpConfig burpConfig) {
        super(parent);
        this.burpConfig = burpConfig;

        setContentPane(contentPane);
        setModal(true);
        getRootPane().setDefaultButton(buttonOK);

        buttonOK.addActionListener(e -> onOK());
        buttonCancel.addActionListener(e -> onCancel());

        // call onCancel() when cross is clicked
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                onCancel();
            }
        });

        // call onCancel() on ESCAPE
        contentPane.registerKeyboardAction(e -> onCancel(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);

        setTitle(Utils.getResourceString("burp_config"));

        ProxyConfig proxyConfig = burpConfig.proxyConfig();

        // Populate the highlight color dropdown, set custom renderer and current item
        comboBoxHighlightColor.setModel(new DefaultComboBoxModel<>(HighlightColor.values()));
        comboBoxHighlightColor.setRenderer(new HighlightComboRenderer());
        comboBoxHighlightColor.setSelectedItem(proxyConfig.highlightColor());

        // Set an event handler to enable/disable highlight color
        checkBoxHighlightJWT.addActionListener(e -> comboBoxHighlightColor.setEnabled(checkBoxHighlightJWT.isSelected()));

        checkBoxHighlightJWT.setSelected(proxyConfig.highlightJWT());
        comboBoxHighlightColor.setEnabled(proxyConfig.highlightJWT());

        IntruderConfig intruderConfig = burpConfig.intruderConfig();

        comboBoxPayloadPosition.setModel(new DefaultComboBoxModel<>(FuzzLocation.values()));
        comboBoxPayloadPosition.setSelectedItem(intruderConfig.fuzzLocation());
        intruderParameterName.setText(intruderConfig.fuzzParameter());
    }

    /**
     * OK clicked, update BurpConfig instance
     */
    private void onOK() {
        ProxyConfig proxyConfig = burpConfig.proxyConfig();
        proxyConfig.setHighlightJWT(checkBoxHighlightJWT.isSelected());
        proxyConfig.setHighlightColor((HighlightColor) comboBoxHighlightColor.getSelectedItem());

        IntruderConfig intruderConfig = burpConfig.intruderConfig();
        intruderConfig.setFuzzParameter(intruderParameterName.getText());
        intruderConfig.setFuzzLocation((FuzzLocation) comboBoxPayloadPosition.getSelectedItem());

        dispose();
    }

    /**
     * Called when the Cancel or X button is pressed. Destroys the window
     */
    private void onCancel() {
        dispose();
    }

    /**
     * Custom list cell renderer to color rows of combo box drop down list.
     */
    private static class HighlightComboRenderer implements ListCellRenderer<HighlightColor> {
        private final ListCellRenderer renderer = new DefaultListCellRenderer();

        /**
         * @param list         The JList we're painting.
         * @param value        The value returned by list.getModel().getElementAt(index).
         * @param index        The cells index.
         * @param isSelected   True if the specified cell was selected.
         * @param cellHasFocus True if the specified cell has the focus.
         * @return updated component with background color set appropriately
         */
        @Override
        public Component getListCellRendererComponent(JList<? extends HighlightColor> list, HighlightColor value, int index, boolean isSelected, boolean cellHasFocus) {
            JLabel label = (JLabel) renderer.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);

            Color background = isSelected ? list.getSelectionBackground() : value.color;
            label.setBackground(background);

            return label;
        }
    }
}