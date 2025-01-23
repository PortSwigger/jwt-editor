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

package com.blackberry.jwteditor.view.dialog.jwks;

import com.blackberry.jwteditor.model.keys.JWKSetParser;
import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.model.keys.KeysModel;
import com.blackberry.jwteditor.utils.Utils;
import com.blackberry.jwteditor.view.rsta.RstaFactory;
import com.blackberry.jwteditor.view.utils.DebouncingDocumentAdapter;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

import javax.swing.*;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.text.ParseException;
import java.util.LinkedList;
import java.util.List;

import static java.awt.Color.PINK;
import static java.awt.Dialog.ModalityType.APPLICATION_MODAL;
import static java.awt.event.KeyEvent.VK_ESCAPE;
import static javax.swing.JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT;
import static javax.swing.JOptionPane.*;

public class JWKSImportDialog extends JDialog {
    private final KeysModel keysModel;
    private final RstaFactory rstaFactory;
    private final List<Key> keys;
    private final Color textAreaKeyInitialBackgroundColor;
    private final Color textAreaKeyInitialCurrentLineHighlightColor;

    private JPanel contentPane;
    private JButton buttonImport;
    private JButton buttonCancel;
    private RSyntaxTextArea textAreaKeysJson;
    private JLabel labelError;

    public JWKSImportDialog(Window parent, KeysModel keysModel, RstaFactory rstaFactory) {
        super(parent, "Import JWKs", APPLICATION_MODAL);

        this.keysModel = keysModel;
        this.rstaFactory = rstaFactory;
        this.keys = new LinkedList<>();

        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                onCancel();
            }
        });

        setContentPane(contentPane);
        getRootPane().setDefaultButton(buttonImport);

        buttonImport.addActionListener(e -> onImport());
        buttonCancel.addActionListener(e -> onCancel());

        contentPane.registerKeyboardAction(
                e -> onCancel(),
                KeyStroke.getKeyStroke(VK_ESCAPE, 0),
                WHEN_ANCESTOR_OF_FOCUSED_COMPONENT
        );

        DocumentListener documentListener = new DebouncingDocumentAdapter(e -> parseJson());
        textAreaKeysJson.getDocument().addDocumentListener(documentListener);

        textAreaKeyInitialBackgroundColor = textAreaKeysJson.getBackground();
        textAreaKeyInitialCurrentLineHighlightColor = textAreaKeysJson.getCurrentLineHighlightColor();
    }

    private void parseJson() {
        textAreaKeysJson.setBackground(textAreaKeyInitialBackgroundColor);
        textAreaKeysJson.setCurrentLineHighlightColor(textAreaKeyInitialCurrentLineHighlightColor);
        buttonImport.setEnabled(false);
        labelError.setText(" ");
        keys.clear();

        if (!textAreaKeysJson.getText().isEmpty()) {
            try {
                List<Key> parsedKeys = new JWKSetParser().parse(textAreaKeysJson.getText());
                keys.addAll(parsedKeys);
                buttonImport.setEnabled(true);
            } catch (ParseException e) {
                textAreaKeysJson.setBackground(PINK);
                textAreaKeysJson.setCurrentLineHighlightColor(PINK);
                labelError.setText(Utils.getResourceString("error_invalid_keys"));
            }
        }
    }

    public List<Key> getKeys() {
       return keys;
    }

    public void display() {
        pack();
        setLocationRelativeTo(getOwner());
        setVisible(true);
    }

    void onImport() {
        boolean keyIdClash = keys.stream()
                .filter(key -> key.getID() != null)
                .anyMatch(key -> keysModel.keyExists(key.getID()));

        // Handle overwrites if a key already exists with the same kid
        if (keyIdClash) {
            if (showConfirmDialog(
                    this,
                    Utils.getResourceString("keys_confirm_overwrite"),
                    Utils.getResourceString("keys_confirm_overwrite_title"),
                    OK_CANCEL_OPTION) != OK_OPTION) {
                keys.clear();
            }
        }

        dispose();
    }

    private void onCancel() {
        keys.clear();
        dispose();
    }

    private void createUIComponents() {
        textAreaKeysJson = rstaFactory.buildDefaultTextArea();
    }
}
