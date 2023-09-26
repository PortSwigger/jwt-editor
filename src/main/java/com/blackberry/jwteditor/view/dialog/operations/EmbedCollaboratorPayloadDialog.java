/*
Author : Dolph Flynn

Copyright 2023 Dolph Flynn

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

import burp.api.montoya.collaborator.CollaboratorPayloadGenerator;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.operations.Attacks;
import com.blackberry.jwteditor.view.dialog.AbstractDialog;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;

import static com.nimbusds.jose.HeaderParameterNames.JWK_SET_URL;
import static com.nimbusds.jose.HeaderParameterNames.X_509_CERT_URL;

public class EmbedCollaboratorPayloadDialog extends AbstractDialog {
    private static final String[] HEADER_LOCATION_VALUES = {JWK_SET_URL, X_509_CERT_URL};

    private final CollaboratorPayloadGenerator collaboratorPayloadGenerator;

    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JComboBox<String> comboBoxAlgorithm;
    private JWS jws;

    public EmbedCollaboratorPayloadDialog(Window parent, JWS jws, CollaboratorPayloadGenerator collaboratorPayloadGenerator) {
        super(parent, "embed_collaborator_payload_attack_dialog_title");
        this.jws = jws;
        this.collaboratorPayloadGenerator = collaboratorPayloadGenerator;

        setContentPane(contentPane);
        getRootPane().setDefaultButton(buttonOK);

        buttonOK.addActionListener(e -> onOK());
        buttonCancel.addActionListener(e -> onCancel());

        // call onCancel() on ESCAPE
        contentPane.registerKeyboardAction(
                e -> onCancel(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT
        );

        comboBoxAlgorithm.setModel(new DefaultComboBoxModel<>(HEADER_LOCATION_VALUES));
        comboBoxAlgorithm.setSelectedIndex(0);
    }

    public JWS getJWS() {
        return jws;
    }

    private void onOK() {
        String selectedLocation = (String) comboBoxAlgorithm.getSelectedItem();
        String JWK_URL = "";

                if("jku".equals(selectedLocation)) {
                    JWK_URL = "https://" + collaboratorPayloadGenerator.generatePayload().toString() + "/jwks.json";
                } else if("x5u".equals(selectedLocation)) {
                    JWK_URL = "https://" + collaboratorPayloadGenerator.generatePayload().toString() + "/cert.pem";
                }

        jws = Attacks.embedCollaboratorPayload(
                jws,
                selectedLocation,
                JWK_URL
        );

        dispose();
    }
}
