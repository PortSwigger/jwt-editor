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

import com.blackberry.jwteditor.exceptions.PemException;
import com.blackberry.jwteditor.exceptions.SigningException;
import com.blackberry.jwteditor.exceptions.UnsupportedKeyException;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.operations.Attacks;
import com.nimbusds.jose.JWSAlgorithm;

import javax.swing.*;
import java.awt.*;
import java.util.List;

import static com.blackberry.jwteditor.view.dialog.operations.LastSigningKeys.Signer.KEY_CONFUSION;
import static com.nimbusds.jose.JWSAlgorithm.*;
import static java.awt.BorderLayout.CENTER;

public class KeyConfusionAttackPanel extends OperationPanel<JWS, JWS> {
    private static final JWSAlgorithm[] ALGORITHMS = {HS256, HS384, HS512};

    private final LastSigningKeys lastSigningKeys;

    private JPanel panel;
    private JComboBox<Key> comboBoxSigningKey;
    private JComboBox<JWSAlgorithm> comboBoxSigningAlgorithm;
    private JCheckBox checkBoxTrailingNewline;

    public KeyConfusionAttackPanel(List<Key> signingKeys, LastSigningKeys lastSigningKeys) {
        super("key_confusion_attack_dialog_title", new Dimension(575, 275));

        this.lastSigningKeys = lastSigningKeys;

        int lastUsedKeyIndex = lastSigningKeys.lastKeyFor(KEY_CONFUSION).map(signingKeys::indexOf).orElse(-1);
        lastUsedKeyIndex = lastUsedKeyIndex == -1 ? 0 : lastUsedKeyIndex;

        comboBoxSigningKey.setModel(new DefaultComboBoxModel<>(signingKeys.toArray(Key[]::new)));
        comboBoxSigningKey.setSelectedIndex(lastUsedKeyIndex);

        comboBoxSigningAlgorithm.setModel(new DefaultComboBoxModel<>(ALGORITHMS));

        add(panel, CENTER);
    }

    @Override
    public JWS performOperation(JWS originalJwt) throws SigningException, PemException, UnsupportedKeyException {
        JWKKey selectedKey = (JWKKey) comboBoxSigningKey.getSelectedItem();
        JWSAlgorithm selectedAlgorithm = (JWSAlgorithm) comboBoxSigningAlgorithm.getSelectedItem();

        lastSigningKeys.recordKeyUse(KEY_CONFUSION, selectedKey);

        return Attacks.hmacKeyConfusion(
                originalJwt,
                selectedKey,
                selectedAlgorithm,
                checkBoxTrailingNewline.isSelected()
        );
    }

    @Override
    public String operationFailedResourceId() {
        return "error_title_unable_to_sign";
    }
}
