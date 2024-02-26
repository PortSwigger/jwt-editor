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
import burp.scanner.ScannerConfig;
import com.blackberry.jwteditor.view.utils.DocumentAdapter;

import javax.swing.*;

import static java.awt.Font.BOLD;


class ScannerConfigView {
    private JPanel mainPanel;
    private JCheckBox checkBoxHeaderInsertionPoint;
    private JTextField scannerParameterName;
    private JLabel scannerLabel;

    ScannerConfigView(UserInterface userInterface, ScannerConfig scannerConfig, boolean isProVersion) {

        checkBoxHeaderInsertionPoint.setEnabled(isProVersion);
        checkBoxHeaderInsertionPoint.setSelected(scannerConfig.enableHeaderJWSInsertionPointLocation());
        checkBoxHeaderInsertionPoint.addActionListener(e -> {
            scannerConfig.setEnableHeaderJWSInsertionPointLocation(checkBoxHeaderInsertionPoint.isSelected());
            scannerParameterName.setEnabled(checkBoxHeaderInsertionPoint.isSelected());
        });

        scannerParameterName.setEnabled(scannerConfig.enableHeaderJWSInsertionPointLocation());
        scannerParameterName.setText(scannerConfig.insertionPointLocationParameterName());
        scannerParameterName.getDocument().addDocumentListener(
                new DocumentAdapter(e -> scannerConfig.setInsertionPointLocationParameterName(scannerParameterName.getText()))
        );

        scannerLabel.setFont(scannerLabel.getFont().deriveFont(BOLD));
        userInterface.applyThemeToComponent(mainPanel);
    }
}
