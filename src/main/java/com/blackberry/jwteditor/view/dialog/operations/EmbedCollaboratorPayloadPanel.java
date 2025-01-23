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

import javax.swing.*;

import static com.nimbusds.jose.HeaderParameterNames.JWK_SET_URL;
import static com.nimbusds.jose.HeaderParameterNames.X_509_CERT_URL;
import static java.awt.BorderLayout.CENTER;

public class EmbedCollaboratorPayloadPanel extends OperationPanel<JWS, JWS> {
    private static final String[] HEADER_LOCATION_VALUES = {JWK_SET_URL, X_509_CERT_URL};

    private final CollaboratorPayloadGenerator collaboratorPayloadGenerator;

    private JPanel panel;
    private JComboBox<String> comboBoxAlgorithm;

    public EmbedCollaboratorPayloadPanel(CollaboratorPayloadGenerator collaboratorPayloadGenerator) {
        super("embed_collaborator_payload_attack_dialog_title");
        this.collaboratorPayloadGenerator = collaboratorPayloadGenerator;

        comboBoxAlgorithm.setModel(new DefaultComboBoxModel<>(HEADER_LOCATION_VALUES));
        comboBoxAlgorithm.setSelectedIndex(0);

        add(panel, CENTER);
    }

    @Override
    public JWS performOperation(JWS originalJwt) {
        String selectedLocation = (String) comboBoxAlgorithm.getSelectedItem();

        return Attacks.embedCollaboratorPayload(
                originalJwt,
                selectedLocation,
                collaboratorPayloadGenerator.generatePayload().toString()
        );
    }
}
