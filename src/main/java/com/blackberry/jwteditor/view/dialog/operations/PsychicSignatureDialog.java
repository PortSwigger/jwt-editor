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

import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.operations.Attacks;
import com.blackberry.jwteditor.view.dialog.AbstractDialog;
import com.nimbusds.jose.JWSAlgorithm;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;

import static com.nimbusds.jose.JWSAlgorithm.*;

public class PsychicSignatureDialog extends AbstractDialog {
    private static final JWSAlgorithm[] ALGORITHMS = {ES256, ES384, ES512};

    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JComboBox<JWSAlgorithm> comboBoxAlgorithm;
    private JWS jws;

    public PsychicSignatureDialog(Window parent, JWS jws) {
        super(parent, "psychic_signature_signing_dialog_title");
        this.jws = jws;

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

        comboBoxAlgorithm.setModel(new DefaultComboBoxModel<>(ALGORITHMS));
        comboBoxAlgorithm.setSelectedIndex(0);
    }

    public JWS getJWS() {
        return jws;
    }

    private void onOK() {
        JWSAlgorithm selectedAlgorithm = (JWSAlgorithm) comboBoxAlgorithm.getSelectedItem();
        jws = Attacks.signWithPsychicSignature(jws, selectedAlgorithm);
        dispose();
    }
}
