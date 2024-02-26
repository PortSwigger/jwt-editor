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
import burp.intruder.FuzzLocation;
import com.blackberry.jwteditor.view.utils.DocumentAdapter;
import com.nimbusds.jose.JWSAlgorithm;

import javax.swing.*;

import static com.blackberry.jwteditor.view.config.IntruderConfigModel.*;
import static java.awt.Font.BOLD;


class IntruderConfigView {
    private JPanel mainPanel;
    private JTextField intruderParameterName;
    private JComboBox comboBoxPayloadPosition;
    private JComboBox comboBoxIntruderSigningKeyId;
    private JLabel intruderLabel;
    private JLabel spacerLabel;
    private JCheckBox resignIntruderJWS;
    private JComboBox comboBoxIntruderSigningAlg;

    IntruderConfigView(UserInterface userInterface, IntruderConfigModel model) {
        intruderParameterName.setText(model.fuzzParameter());
        intruderParameterName.getDocument().addDocumentListener(
                new DocumentAdapter(e -> model.setFuzzParameter(intruderParameterName.getText()))
        );

        comboBoxPayloadPosition.setModel(new DefaultComboBoxModel<>(model.fuzzLocations()));
        comboBoxPayloadPosition.setSelectedItem(model.fuzzLocation());
        comboBoxPayloadPosition.addActionListener(e -> model.setFuzzLocation((FuzzLocation) comboBoxPayloadPosition.getSelectedItem()));

        comboBoxIntruderSigningKeyId.setModel(new DefaultComboBoxModel<>(model.signingKeyIds()));
        comboBoxIntruderSigningKeyId.setSelectedItem(model.signingKeyId());
        comboBoxIntruderSigningKeyId.setEnabled(model.hasSigningKeys());
        comboBoxIntruderSigningKeyId.addActionListener(e -> model.setSigningKeyId((String) comboBoxIntruderSigningKeyId.getSelectedItem()));

        comboBoxIntruderSigningAlg.setModel(new DefaultComboBoxModel<>(model.signingAlgorithms()));
        comboBoxIntruderSigningAlg.setSelectedItem(model.signingAlgorithm());
        comboBoxIntruderSigningAlg.setEnabled(model.hasSigningKeys());
        comboBoxIntruderSigningAlg.addActionListener(e -> model.setSigningAlgorithm((JWSAlgorithm) comboBoxIntruderSigningAlg.getSelectedItem()));

        resignIntruderJWS.setEnabled(model.hasSigningKeys());
        resignIntruderJWS.setSelected(model.resign());
        resignIntruderJWS.addActionListener(e -> model.setResign(resignIntruderJWS.isSelected()));

        intruderLabel.setFont(intruderLabel.getFont().deriveFont(BOLD));
        userInterface.applyThemeToComponent(mainPanel);

        updateControls(model.hasSigningKeys());

        model.addPropertyChangeListener(evt -> {
            switch (evt.getPropertyName()) {
                case SIGNING_KEYS_UPDATED:
                    comboBoxIntruderSigningKeyId.setModel(new DefaultComboBoxModel<>((String[]) evt.getNewValue()));
                    comboBoxIntruderSigningKeyId.setSelectedItem(model.signingKeyId());
                    updateControls(model.hasSigningKeys());
                    resignIntruderJWS.setSelected(model.resign());
                    break;

                case SIGNING_ALGORITHMS_UPDATED:
                    comboBoxIntruderSigningAlg.setModel(new DefaultComboBoxModel((JWSAlgorithm[]) evt.getNewValue()));
                    break;

                case SELECTED_KEY_UPDATED:
                    comboBoxIntruderSigningKeyId.setSelectedItem(evt.getNewValue());
                    break;

                case SELECTED_ALGORITHM_UPDATED:
                    comboBoxIntruderSigningAlg.setSelectedItem(evt.getNewValue());
                    break;

                case RESIGN_UPDATED:
                    resignIntruderJWS.setSelected((Boolean) evt.getNewValue());
                    break;
            }
        });
    }

    private void updateControls(boolean hasSigningKeys) {
        resignIntruderJWS.setEnabled(hasSigningKeys);
        comboBoxIntruderSigningKeyId.setEnabled(hasSigningKeys);
        comboBoxIntruderSigningAlg.setEnabled(hasSigningKeys);
    }
}
