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

import com.blackberry.jwteditor.exceptions.PemException;
import com.blackberry.jwteditor.exceptions.UnsupportedKeyException;
import com.blackberry.jwteditor.model.keys.JWKKeyFactory;
import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.model.keys.KeysModel;
import com.blackberry.jwteditor.utils.JSONUtils;
import com.blackberry.jwteditor.utils.PEMUtils;
import com.blackberry.jwteditor.utils.Utils;
import com.blackberry.jwteditor.view.rsta.RstaFactory;
import com.blackberry.jwteditor.view.utils.DebouncingDocumentAdapter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;

import javax.swing.*;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.text.ParseException;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

import static javax.swing.JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT;
import static javax.swing.SwingUtilities.invokeLater;

public class AsymmetricKeyDialog extends KeyDialog {
    private final AsymmetricKeyDialogMode mode;
    private final RstaFactory rstaFactory;

    private Color textAreaKeyInitialBackgroundColor;
    private Color textAreaKeyInitialCurrentLineHighlightColor;
    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JComboBox<Object> comboBoxKeySize;
    private JButton buttonGenerate;
    private RSyntaxTextArea textAreaKey;
    private JRadioButton radioButtonJWK;
    private JRadioButton radioButtonPEM;
    private JLabel labelError;
    private JTextField textFieldKeyId;
    private JLabel keySizeLabel;

    private JWK jwk;

    AsymmetricKeyDialog(
            Window parent,
            KeysModel keysModel,
            RstaFactory rstaFactory,
            AsymmetricKeyDialogMode mode,
            JWK jwk) {
        super(parent, mode.resourceTitleId(), jwk == null ? null : jwk.getKeyID(), keysModel);

        this.mode = mode;
        this.rstaFactory = rstaFactory;
        this.jwk = jwk;

        setContentPane(contentPane);
        getRootPane().setDefaultButton(buttonOK);

        buttonOK.addActionListener(e -> onOK());
        buttonCancel.addActionListener(e -> onCancel());

        // call onCancel() on ESCAPE
        contentPane.registerKeyboardAction(
                e -> onCancel(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                WHEN_ANCESTOR_OF_FOCUSED_COMPONENT
        );

        keySizeLabel.setText(Utils.getResourceString(mode.resourceLabelId()));
        comboBoxKeySize.setModel(new DefaultComboBoxModel<>(mode.keyOptions()));
        comboBoxKeySize.setSelectedItem(mode.selectedKeyOption(jwk));

        // Add event listeners for the generate button being pressed, the key format radio button changing, or the text
        // content being updated
        radioButtonJWK.addChangeListener(e -> onKeyFormatChanged());
        buttonGenerate.addActionListener(e -> generateKey());

        DocumentListener documentListener = new DebouncingDocumentAdapter(e -> parseJson());

        textAreaKey.getDocument().addDocumentListener(documentListener);
        textFieldKeyId.getDocument().addDocumentListener(documentListener);

        if (jwk != null) {
            textFieldKeyId.setText(jwk.getKeyID());
        }

        // If not in edit mode setting the contents of the text field before the window has opened causes the horizontal
        // scroll pane not to initialize properly, so do this after the window open event
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowOpened(WindowEvent e) {
                onKeyFormatChanged();
            }
        });
    }

    private void setFormEnabled(boolean enabled) {
        buttonOK.setEnabled(enabled);
    }

    private void parseJson() {
        if (textAreaKeyInitialBackgroundColor == null) {
            textAreaKeyInitialBackgroundColor = textAreaKey.getBackground();
            textAreaKeyInitialCurrentLineHighlightColor = textAreaKey.getCurrentLineHighlightColor();
        }

        JWK tempJWK = null;

        // Get the text contents
        String key = textAreaKey.getText();

        // Clear any error formatting
        setFormEnabled(true);
        textAreaKey.setBackground(textAreaKeyInitialBackgroundColor);
        textAreaKey.setCurrentLineHighlightColor(textAreaKeyInitialCurrentLineHighlightColor);
        textFieldKeyId.setBackground(textAreaKeyInitialBackgroundColor);
        labelError.setText(" ");

        boolean keyError = false;
        boolean keyIDError = false;
        if (key.isEmpty()) {
            // Disable OK if the text entry is empty
            setFormEnabled(false);
        } else {
            try {
                // If JWK is selected, try to parse as a JWK
                if (radioButtonJWK.isSelected()) {
                    tempJWK = JWK.parse(key);

                    if (tempJWK.getKeyID() == null) {
                        keyError = true;
                        labelError.setText(Utils.getResourceString("error_missing_kid"));
                    }

                    // Restricting RSA private keys to their full form at the moment as there is an issue with PEM parsing these keys
                    if (tempJWK instanceof RSAKey && tempJWK.isPrivate() && ((RSAKey) tempJWK).getFirstPrimeFactor() == null) {
                        keyError = true;
                        labelError.setText(Utils.getResourceString("error_invalid_key"));
                    }
                }
                // If not, try to parse the PEM and convert to a JWK
                else {
                    tempJWK = mode.pemToJWK(key, textFieldKeyId.getText());

                    // Check the key id entry is set in PEM mode
                    if (textFieldKeyId.getText().isEmpty()) {
                        keyIDError = true;
                        labelError.setText(Utils.getResourceString("error_missing_kid"));
                    }
                }

                // Check the parsed JWK is the correct type for the window mode
                if (tempJWK.getKeyType() != mode.keyType()) {
                    keyError = true;
                    labelError.setText(Utils.getResourceString("error_invalid_key_type"));
                }

            } catch (ParseException | IllegalArgumentException | PemException e) {
                // Set the error state if any parse errors are encountered
                keyError = true;
                if (textFieldKeyId.getText().isEmpty()) {
                    keyIDError = true;
                }
                labelError.setText(Utils.getResourceString("error_invalid_key"));
            }

        }

        // If the key ID is invalid, disable OK and highlight the key id text entry
        if (keyIDError) {
            setFormEnabled(false);
            textFieldKeyId.setBackground(Color.PINK);
        }

        // If the key text is invalid, disable OK and highlight the key text entry
        if (keyError) {
            setFormEnabled(false);
            textAreaKey.setBackground(Color.PINK);
            textAreaKey.setCurrentLineHighlightColor(Color.PINK);
        }

        // Set the parsed JWK if there are no errors, set to null otherwise
        jwk = keyError || keyIDError ? null : tempJWK;
    }

    /**
     * Handler for the key format radio button changing
     */
    private void onKeyFormatChanged() {
        // Change from PEM to JWK
        if (radioButtonJWK.isSelected()) {
            // If the PEM has not been parsed to a JWK, clear the JWK entry
            // Otherwise, serialized the JWK to JSON and set the contents of the text box
            String text = jwk == null ? "" : JSONUtils.prettyPrintJSON(jwk.toJSONString());
            textAreaKey.setText(text);

            // Ordering is important here, these must come after the conversion above, otherwise they will trigger the
            // event handlers and clear the stored jwk
            textAreaKey.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
        }
        // Change from JWK to PEM
        else {
            if (jwk == null) {
                // If the JWK has not been parsed, clear the PEM entry and key id text box
                textFieldKeyId.setText("");
                textAreaKey.setText("");
            } else {
                // Otherwise, serialized the JWK to PEM and set the contents of the text box
                try {
                    // Store a temporary copy of the JWK as setting the first field will overwrite the stored JWK
                    JWK tempJWK = jwk;
                    textFieldKeyId.setText(tempJWK.getKeyID());
                    textAreaKey.setText(PEMUtils.jwkToPem(tempJWK));
                } catch (PemException e) {
                    textFieldKeyId.setText("");
                    textAreaKey.setText("");
                }
            }

            // Ordering is important here, these must come after the conversion above, otherwise they will clear the
            // event handlers and clear the stored jwk
            textAreaKey.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
        }
    }

    private void generateKey() {
        // Get the selected key size
        Object parameters = comboBoxKeySize.getSelectedItem();
        String keyId = textFieldKeyId.getText().isEmpty() ? UUID.randomUUID().toString() : textFieldKeyId.getText();

        enableOrDisableControls(false);

        // Generate the new key on a background thread as this may be long running
        new SwingWorker<JWK, Void>() {
            @Override
            protected JWK doInBackground() throws Exception {
                return mode.generateNewKey(keyId, parameters);
            }

            /**
             * Called when doInBackground has finished
             */
            @Override
            protected void done() {
                try {
                    // Get the return value of doInBackground
                    JWK jwk = get();

                    // Set the key text fields based on whether JWK/PEM is selected in the radio button
                    String keyData = radioButtonJWK.isSelected()
                            ? JSONUtils.prettyPrintJSON(jwk.toJSONString())
                            : PEMUtils.jwkToPem(jwk);

                    invokeLater(() -> {
                        textFieldKeyId.setText(jwk.getKeyID());
                        textAreaKey.setText(keyData);
                    });
                } catch (PemException | InterruptedException | ExecutionException e) {
                    labelError.setText(Utils.getResourceString("error_key_generation"));
                }

                // Re-enable the form
                enableOrDisableControls(true);
            }
        }.execute();
    }

    private void enableOrDisableControls(boolean enabled) {
        // Disable the form controls during keygen
        comboBoxKeySize.setEnabled(enabled);
        buttonGenerate.setEnabled(enabled);
        textAreaKey.setEnabled(enabled);
        textFieldKeyId.setEnabled(enabled);
        buttonOK.setEnabled(enabled);
        radioButtonJWK.setEnabled(enabled);
        radioButtonPEM.setEnabled(enabled);
    }

    /**
     * Get the new/modified key resulting from the operations of this dialog
     *
     * @return the new/modified JWK
     */
    public Key getKey() {
        try {
            return jwk == null ? null : JWKKeyFactory.from(jwk);
        } catch (UnsupportedKeyException e) {
            return null;
        }
    }

    /**
     * Called when the Cancel or X button is pressed. Set the changed key to null and destroy the window
     */
    @Override
    void onCancel() {
        jwk = null;
        dispose();
    }

    private void createUIComponents() {
        textAreaKey = rstaFactory.buildDefaultTextArea();
    }
}
