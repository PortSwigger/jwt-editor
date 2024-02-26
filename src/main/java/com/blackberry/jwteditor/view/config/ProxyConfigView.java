/*
Author : Dolph Flynn

Copyright 2024 Dolph Flynn

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

package com.blackberry.jwteditor.view.config;

import burp.api.montoya.ui.UserInterface;
import burp.proxy.HighlightColor;
import burp.proxy.ProxyConfig;

import javax.swing.*;
import java.awt.*;

import static java.awt.Font.BOLD;


class ProxyConfigView {
    private JPanel mainPanel;
    private JCheckBox checkBoxHighlightJWT;
    private JComboBox comboBoxHighlightColor;
    private JLabel proxyLabel;

    ProxyConfigView(UserInterface userInterface, ProxyConfig proxyConfig) {
        checkBoxHighlightJWT.setSelected(proxyConfig.highlightJWT());

        checkBoxHighlightJWT.addActionListener(e -> {
            comboBoxHighlightColor.setEnabled(checkBoxHighlightJWT.isSelected());
            proxyConfig.setHighlightJWT(checkBoxHighlightJWT.isSelected());
        });

        comboBoxHighlightColor.setModel(new DefaultComboBoxModel<>(HighlightColor.values()));
        comboBoxHighlightColor.setSelectedItem(proxyConfig.highlightColor());
        comboBoxHighlightColor.setEnabled(proxyConfig.highlightJWT());
        comboBoxHighlightColor.addActionListener(e -> proxyConfig.setHighlightColor((HighlightColor) comboBoxHighlightColor.getSelectedItem()));

        proxyLabel.setFont(proxyLabel.getFont().deriveFont(BOLD));
        userInterface.applyThemeToComponent(mainPanel);

        comboBoxHighlightColor.setRenderer(new HighlightComboRenderer());
    }

    private static class HighlightComboRenderer implements ListCellRenderer<HighlightColor> {
        private final ListCellRenderer renderer = new DefaultListCellRenderer();

        @Override
        public Component getListCellRendererComponent(JList<? extends HighlightColor> list, HighlightColor value, int index, boolean isSelected, boolean cellHasFocus) {
            JLabel label = (JLabel) renderer.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);

            Color background = isSelected ? list.getSelectionBackground() : value.color;
            label.setBackground(background);

            return label;
        }
    }
}
