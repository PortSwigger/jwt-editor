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

package com.blackberry.jwteditor.view.dialog.keys;

import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.model.keys.KeysModel;
import com.blackberry.jwteditor.model.keys.PasswordKey;
import com.blackberry.jwteditor.view.utils.DocumentAdapter;

import javax.swing.*;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.util.UUID;

/**
 * "New Password" dialog for Keys tab
 */
public class PasswordDialog extends KeyDialog {
    private static final String TITLE_RESOURCE_ID = "password";

    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JTextField textFieldPassword;
    private JSpinner spinnerSaltLength;
    private JSpinner spinnerIterations;
    private JTextField textFieldKeyId;

    public PasswordDialog(Window parent, KeysModel keysModel) {
        this(parent, keysModel, null, "", 8, 1000);
    }

    public PasswordDialog(Window parent, KeysModel keysModel, PasswordKey key) {
        this(parent, keysModel, key.getID(), key.getPassword(), key.getSaltLength(), key.getIterations());
    }

    private PasswordDialog(Window parent, KeysModel keysModel, String keyId, String password, int saltLength, int iterations) {
        super(parent, TITLE_RESOURCE_ID, keyId, keysModel);

        keyId = keyId == null ? UUID.randomUUID().toString() : keyId;

        setContentPane(contentPane);
        getRootPane().setDefaultButton(buttonOK);

        buttonOK.addActionListener(e -> onOK());
        buttonCancel.addActionListener(e -> onCancel());

        // call onCancel() on ESCAPE
        contentPane.registerKeyboardAction(e -> onCancel(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);

        // Initialise the iterations spinner
        SpinnerNumberModel spinnerModelIterations = new SpinnerNumberModel();
        spinnerModelIterations.setStepSize(1000);
        spinnerModelIterations.setMinimum(1);
        spinnerIterations.setModel(spinnerModelIterations);

        // Initialise the salt length spinner
        SpinnerNumberModel spinnerModeSalt = new SpinnerNumberModel();
        spinnerModeSalt.setMinimum(1);
        spinnerSaltLength.setModel(spinnerModeSalt);

        DocumentListener documentListener = new DocumentAdapter(e -> checkInput());

        // Attach event handlers for the inputs changing
        textFieldPassword.getDocument().addDocumentListener(documentListener);
        textFieldKeyId.getDocument().addDocumentListener(documentListener);
        spinnerSaltLength.addChangeListener(e -> checkInput());
        spinnerIterations.addChangeListener(e -> checkInput());

        // Set the inputs to their initial values, triggering the event handlers to check the input
        textFieldKeyId.setText(keyId);
        textFieldPassword.setText(password);
        spinnerModeSalt.setValue(saltLength);
        spinnerModelIterations.setValue(iterations);
    }

    /**
     * Event handler for checking the inputs are valid when any values change
     */
    private void checkInput() {
        // Check that the password and key id values are set, enable/disable OK based on the result
        buttonOK.setEnabled(!textFieldKeyId.getText().isEmpty() && !textFieldPassword.getText().isEmpty());
    }

    @Override
    Key constructKey() {
        return new PasswordKey(textFieldKeyId.getText(),
                textFieldPassword.getText(),
                (Integer) spinnerSaltLength.getValue(),
                (Integer) spinnerIterations.getValue()
        );
    }
}
