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

import com.blackberry.jwteditor.exceptions.UnsupportedKeyException;
import com.blackberry.jwteditor.model.keys.JWKKeyFactory;
import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.model.keys.KeysModel;
import com.blackberry.jwteditor.utils.JSONUtils;
import com.blackberry.jwteditor.utils.Utils;
import com.blackberry.jwteditor.view.rsta.RstaFactory;
import com.blackberry.jwteditor.view.utils.DebouncingDocumentAdapter;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

import javax.swing.*;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.UUID;

import static java.awt.event.KeyEvent.VK_ESCAPE;
import static java.nio.charset.StandardCharsets.UTF_8;
import static javax.swing.JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT;

public class SymmetricKeyDialog extends KeyDialog {
    private static final String TITLE_RESOURCE_ID = "keys_new_title_symmetric";

    private final RstaFactory rstaFactory;
    private final Color textAreaKeyInitialBackgroundColor;
    private final Color textAreaKeyInitialCurrentLineHighlightColor;
    private final SecureRandom rng;

    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JSpinner spinnerKeySize;
    private JButton buttonGenerate;
    private RSyntaxTextArea textAreaKey;
    private JLabel labelError;
    private JRadioButton specifySecretRadioButton;
    private JRadioButton randomSecretRadioButton;
    private JTextField specificSecretTextField;
    private JTextField textFieldKeyId;

    private OctetSequenceKey jwk;

    public SymmetricKeyDialog(Window parent, KeysModel keysModel, RstaFactory rstaFactory, OctetSequenceKey jwk) {
        super(parent, TITLE_RESOURCE_ID, jwk == null ? null : jwk.getKeyID(), keysModel);

        this.rstaFactory = rstaFactory;
        this.rng = new SecureRandom();

        setContentPane(contentPane);
        getRootPane().setDefaultButton(buttonOK);

        buttonOK.addActionListener(e -> onOK());
        buttonCancel.addActionListener(e -> onCancel());

        // call onCancel() on ESCAPE
        contentPane.registerKeyboardAction(
                e -> onCancel(),
                KeyStroke.getKeyStroke(VK_ESCAPE, 0),
                WHEN_ANCESTOR_OF_FOCUSED_COMPONENT
        );

        spinnerKeySize.setModel(new SpinnerNumberModel(128, 0, null, 8));

        spinnerKeySize.addChangeListener(e -> {
            int value = (int) spinnerKeySize.getValue();

            // Round any manually entered values up to the nearest number of bytes
            if (value == 0 || value % 8 > 0) {
                int nextByteSize = ((value / 8) + 1) * 8;
                spinnerKeySize.setValue(nextByteSize);
            }
        });

        randomSecretRadioButton.addItemListener(e -> {
            specificSecretTextField.setEnabled(false);
            spinnerKeySize.setEnabled(true);
        });

        specifySecretRadioButton.addItemListener(e -> {
            specificSecretTextField.setEnabled(true);
            spinnerKeySize.setEnabled(false);
        });

        // Attach event listeners for Generate button and text entry changing
        buttonGenerate.addActionListener(e -> generateKey());

        DocumentListener documentListener = new DebouncingDocumentAdapter(e -> parseJson());
        textAreaKey.getDocument().addDocumentListener(documentListener);

        textAreaKeyInitialBackgroundColor = textAreaKey.getBackground();
        textAreaKeyInitialCurrentLineHighlightColor = textAreaKey.getCurrentLineHighlightColor();

        // Set the key id and key value fields if provided
        if (jwk != null) {
            textAreaKey.setText(JSONUtils.prettyPrintJSON(jwk.toJSONString()));
            spinnerKeySize.setValue(jwk.size());
            textFieldKeyId.setText(jwk.getKeyID());
        }
    }

    private void parseJson() {
        // Clear the error state. Disable OK while parsing
        textAreaKey.setBackground(textAreaKeyInitialBackgroundColor);
        textAreaKey.setCurrentLineHighlightColor(textAreaKeyInitialCurrentLineHighlightColor);
        buttonOK.setEnabled(false);
        labelError.setText(" ");
        jwk = null;

        // If there is a text in the text entry
        if (!textAreaKey.getText().isEmpty()) {
            try {
                // Try to parse as a symmetric key JWK
                OctetSequenceKey octetSequenceKey = OctetSequenceKey.parse(textAreaKey.getText());

                // Check the JWK contains a 'kid' value, set form to error mode if not
                if (octetSequenceKey.getKeyID() == null) {
                    textAreaKey.setBackground(Color.PINK);
                    textAreaKey.setCurrentLineHighlightColor(Color.PINK);
                    labelError.setText(Utils.getResourceString("error_missing_kid"));
                } else {
                    // No errors, enable the OK button
                    buttonOK.setEnabled(true);
                    jwk = octetSequenceKey;
                }

            } catch (ParseException e) {
                // Set form to error mode if JWK parsing fails
                textAreaKey.setBackground(Color.PINK);
                textAreaKey.setCurrentLineHighlightColor(Color.PINK);
                labelError.setText(Utils.getResourceString("error_invalid_key"));
            }
        }
    }

    private void generateKey() {
        String keyId = textFieldKeyId.getText().isBlank()
                ? UUID.randomUUID().toString()
                : textFieldKeyId.getText().trim();

        int keySizeBits = (int) spinnerKeySize.getValue();
        int keySizeBytes = keySizeBits / 8;
        OctetSequenceKey octetSequenceKey;

        if (randomSecretRadioButton.isSelected()) {
            // Generate a new symmetric key based on the key size selected in the combobox
            byte[] key = new byte[keySizeBytes];
            rng.nextBytes(key);

            // Use the Builder directly to skip length checks - the spinner model enforces these
            octetSequenceKey = new OctetSequenceKey.Builder(key).keyID(keyId).build();
        } else {
            Base64URL key = Base64URL.encode(specificSecretTextField.getText().getBytes(UTF_8));
            octetSequenceKey = new OctetSequenceKey.Builder(key).keyID(keyId).build();
        }

        // Set the text area contents to the JSON form of the newly generated key
        textAreaKey.setText(JSONUtils.prettyPrintJSON(octetSequenceKey.toJSONString()));
        textFieldKeyId.setText(keyId);
    }

    @Override
    Key constructKey() {
        try {
            return jwk == null ? null : JWKKeyFactory.from(jwk);
        } catch (UnsupportedKeyException ignored) {
            return null;
        }
    }

    private void createUIComponents() {
        textAreaKey = rstaFactory.buildDefaultTextArea();
    }
}
