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

package com.blackberry.jwteditor.view.dialog.operations;

import com.blackberry.jwteditor.exceptions.EncryptionException;
import com.blackberry.jwteditor.model.jose.JWE;
import com.blackberry.jwteditor.model.jose.JWEFactory;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.keys.Key;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;

import javax.swing.*;
import java.awt.*;
import java.util.List;

import static java.awt.BorderLayout.CENTER;

public class EncryptPanel extends OperationPanel<JWE, JWS> {
    private JPanel panel;
    private JComboBox<EncryptionMethod> comboBoxCEK;
    private JComboBox<JWEAlgorithm> comboBoxKEK;
    private JComboBox<Key> comboBoxEncryptionKey;

    public EncryptPanel(List<Key> encryptionKeys) {
        super("encrypt_dialog_title", new Dimension(600, 325));

        // Convert encryptionKeys List to Array
        Key[] encryptionKeysArray = new Key[encryptionKeys.size()];
        encryptionKeys.toArray(encryptionKeysArray);

        // Populate the encryption keys dropdown with the provided keys, attach a listener to update the Key Encryption Algorithm dropdown when this changes
        comboBoxEncryptionKey.setModel(new DefaultComboBoxModel<>(encryptionKeysArray));
        comboBoxEncryptionKey.addActionListener(e -> updateKEK());

        // Attach a listener to Key Encryption Algorithm dropdown to update the Content Encryption Algorithm dropdown when selected key encryption algorithm changes
        comboBoxKEK.addActionListener(e -> updateCEK());

        // Set the encryption key to be the first value. This will trigger the event handlers setting the other two dropdowns
        comboBoxEncryptionKey.setSelectedIndex(0);

        add(panel, CENTER);
    }

    /**
     * Event handler called when the Encryption Key dropdown is changed
     */
    private void updateKEK() {
        // Get the selected encryption key
        Key selectedKey = (Key) comboBoxEncryptionKey.getSelectedItem();

        // Get the valid Key Encryption Algorithms for the selected key
        //noinspection ConstantConditions
        JWEAlgorithm[] kekAlgorithms = selectedKey.getKeyEncryptionKeyAlgorithms();

        // Populate the Key Encryption Algorithms with the valid values
        comboBoxKEK.setModel(new DefaultComboBoxModel<>(kekAlgorithms));

        // Set the first value to selected. Otherwise disable the dropdown if there are no valid algorithms
        if (kekAlgorithms.length > 0) {
            comboBoxKEK.setSelectedIndex(0);
            comboBoxKEK.setEnabled(true);
        } else {
            comboBoxKEK.setEnabled(false);
        }

        // Trigger an update of the Content Encryption Algorithm dropdown
        updateCEK();
    }

    /**
     * Event handler called when the Key Encryption Algorithm dropdown is changed
     */
    private void updateCEK() {

        // Get the selected encryption key
        Key selectedKey = (Key) comboBoxEncryptionKey.getSelectedItem();

        if (selectedKey != null) {
            // Get the selected Key Encryption Algorithm
            JWEAlgorithm selectedKekAlgorithm = (JWEAlgorithm) comboBoxKEK.getSelectedItem();
            if (selectedKekAlgorithm != null) {

                // Get the valid Content Encryption Algorithms for the selected Key Encryption Algorithm
                EncryptionMethod[] cekAlgorithms = selectedKey.getContentEncryptionKeyAlgorithms(selectedKekAlgorithm);

                // Populate the Content Encryption Algorithms with the valid values
                comboBoxCEK.setModel(new DefaultComboBoxModel<>(cekAlgorithms));

                // Set the first value to selected. Otherwise disable the dropdown if there are no valid algorithms
                if (cekAlgorithms.length > 0) {
                    comboBoxCEK.setSelectedIndex(0);
                    comboBoxCEK.setEnabled(true);
                    fireValidityEvent(true);
                } else {
                    comboBoxCEK.setEnabled(false);
                }
            } else {
                // Disable the form and the Content Encryption Algorithm dropdown if there is no Key Encryption Algorithm selected
                comboBoxCEK.setModel(new DefaultComboBoxModel<>());
                comboBoxCEK.setEnabled(false);
                fireValidityEvent(false);
            }
        } else {
            // Disable the form and the Content Encryption Algorithm dropdown if there is no Encryption Key selected
            comboBoxCEK.setModel(new DefaultComboBoxModel<>());
            comboBoxCEK.setEnabled(false);
            fireValidityEvent(false);
        }
    }

    private void fireValidityEvent(boolean isValid) {
        firePropertyChange(VALIDITY_EVENT, !isValid, isValid);
    }

    @Override
    public JWE performOperation(JWS originalJwt) throws EncryptionException {
        Key selectedKey = (Key) comboBoxEncryptionKey.getSelectedItem();
        JWEAlgorithm selectedKek = (JWEAlgorithm) comboBoxKEK.getSelectedItem();
        EncryptionMethod selectedCek = (EncryptionMethod) comboBoxCEK.getSelectedItem();

        return JWEFactory.encrypt(originalJwt, selectedKey, selectedKek, selectedCek);
    }

    @Override
    public String operationFailedResourceId() {
        return "error_title_unable_to_encrypt";
    }
}
