/*

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

import com.blackberry.jwteditor.exceptions.SigningException;
import com.blackberry.jwteditor.exceptions.UnsupportedKeyException;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.operations.Attacks;
import com.nimbusds.jose.JWSAlgorithm;

import javax.swing.*;

import static com.nimbusds.jose.JWSAlgorithm.*;
import static java.awt.BorderLayout.CENTER;

public class EmptyKeySigningPanel extends OperationPanel<JWS, JWS> {
    private static final JWSAlgorithm[] ALGORITHMS = {HS256, HS384, HS512};

    private JPanel panel;
    private JComboBox<JWSAlgorithm> comboBoxAlgorithm;

    public EmptyKeySigningPanel() {
        super("empty_key_signing_dialog_title");

        comboBoxAlgorithm.setModel(new DefaultComboBoxModel<>(ALGORITHMS));
        comboBoxAlgorithm.setSelectedIndex(0);

        add(panel, CENTER);
    }

    @Override
    public JWS performOperation(JWS originalJwt) throws SigningException, UnsupportedKeyException {
        JWSAlgorithm selectedAlgorithm = (JWSAlgorithm) comboBoxAlgorithm.getSelectedItem();

        return Attacks.signWithEmptyKey(originalJwt, selectedAlgorithm);
    }

    @Override
    public String operationFailedResourceId() {
        return "error_title_unable_to_sign";
    }
}
