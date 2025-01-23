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

import com.blackberry.jwteditor.exceptions.SigningException;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.jose.JWSFactory;
import com.blackberry.jwteditor.model.jose.JWSFactory.SigningUpdateMode;
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.operations.Attacks;
import com.blackberry.jwteditor.view.dialog.operations.LastSigningKeys.Signer;
import com.nimbusds.jose.JWSAlgorithm;

import javax.swing.*;
import java.awt.*;
import java.util.List;

import static com.blackberry.jwteditor.model.jose.JWSFactory.SigningUpdateMode.*;
import static java.awt.BorderLayout.CENTER;

public class SigningPanel extends OperationPanel<JWS, JWS> {

    public enum Mode {
        NORMAL("sign_dialog_title", Signer.NORMAL),
        EMBED_JWK("embed_jwk_attack_dialog_title", Signer.EMBED_JWK);

        final Signer signer;

        private final String titleResourceId;

        Mode(String titleResourceId, Signer embedJwk) {
            this.titleResourceId = titleResourceId;
            this.signer = embedJwk;
        }

        Dimension dimension() {
            return switch (this) {
                case NORMAL -> new Dimension(500, 375);
                case EMBED_JWK -> new Dimension(500, 250);
            };
        }
    }

    private JPanel panel;
    private JComboBox<Key> comboBoxSigningKey;
    private JComboBox<JWSAlgorithm> comboBoxSigningAlgorithm;
    private JPanel panelOptions;
    private JRadioButton radioButtonUpdateGenerateAlg;
    private JRadioButton radioButtonUpdateGenerateJWT;
    private JRadioButton radioButtonUpdateGenerateNone;

    private final Mode mode;
    private final LastSigningKeys lastSigningKeys;

    public SigningPanel(List<Key> signingKeys, Mode mode, LastSigningKeys lastSigningKeys) {
        super(mode.titleResourceId, mode.dimension());
        this.mode = mode;
        this.lastSigningKeys = lastSigningKeys;

        // Convert the signingKeys from a List to an Array
        Key[] signingKeysArray = new Key[signingKeys.size()];
        signingKeys.toArray(signingKeysArray);

        // Populate the signing keys dropdown
        comboBoxSigningKey.setModel(new DefaultComboBoxModel<>(signingKeysArray));

        // Set an event handler to update the signing algorithms dropdown when the selected key changes
        comboBoxSigningKey.addActionListener(e -> {
            Key selectedKey = (Key) comboBoxSigningKey.getSelectedItem();
            //noinspection ConstantConditions
            comboBoxSigningAlgorithm.setModel(new DefaultComboBoxModel<>(selectedKey.getSigningAlgorithms()));
        });

        int lastUsedKeyIndex = lastSigningKeys.lastKeyFor(mode.signer).map(signingKeys::indexOf).orElse(-1);
        lastUsedKeyIndex = lastUsedKeyIndex == -1 ? 0 : lastUsedKeyIndex;
        comboBoxSigningKey.setSelectedIndex(lastUsedKeyIndex);

        // If the dialog is being used for the embedded JWK attack, hide the Header Options
        if (mode != Mode.NORMAL) {
            panelOptions.setVisible(false);
        }

        add(panel, CENTER);
    }

    @Override
    public JWS performOperation(JWS originalJwt) throws SigningException, NoSuchFieldException, IllegalAccessException {
        // Get the selected signing key and algorithm
        JWKKey selectedKey = (JWKKey) comboBoxSigningKey.getSelectedItem();
        JWSAlgorithm selectedAlgorithm = (JWSAlgorithm) comboBoxSigningAlgorithm.getSelectedItem();

        lastSigningKeys.recordKeyUse(mode.signer, selectedKey);

        // Get the header update mode based on the selected radio button, convert to the associated enum value
        SigningUpdateMode signingUpdateMode;

        if (radioButtonUpdateGenerateAlg.isSelected()) {
            signingUpdateMode = UPDATE_ALGORITHM_ONLY;
        } else if (radioButtonUpdateGenerateJWT.isSelected()) {
            signingUpdateMode = UPDATE_ALGORITHM_TYPE_AND_KID;
        } else {
            signingUpdateMode = DO_NOT_MODIFY_HEADER;
        }

        return switch (mode) {
            case NORMAL -> JWSFactory.sign(selectedKey, selectedAlgorithm, signingUpdateMode, originalJwt);
            case EMBED_JWK -> Attacks.embeddedJWK(originalJwt, selectedKey, selectedAlgorithm);
        };
    }

    @Override
    public String operationFailedResourceId() {
        return "error_title_unable_to_sign";
    }
}
