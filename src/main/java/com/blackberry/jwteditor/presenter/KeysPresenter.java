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

package com.blackberry.jwteditor.presenter;

import com.blackberry.jwteditor.exceptions.PemException;
import com.blackberry.jwteditor.model.jose.JWKSet;
import com.blackberry.jwteditor.model.keys.*;
import com.blackberry.jwteditor.model.persistence.KeysModelPersistence;
import com.blackberry.jwteditor.utils.PEMUtils;
import com.blackberry.jwteditor.utils.Utils;
import com.blackberry.jwteditor.view.dialog.keys.KeyDialog;
import com.blackberry.jwteditor.view.dialog.keys.KeysDialogFactory;
import com.blackberry.jwteditor.view.keys.KeysView;
import com.nimbusds.jose.jwk.JWK;

import javax.swing.*;
import java.util.List;
import java.util.Objects;
import java.util.stream.IntStream;

import static com.blackberry.jwteditor.utils.JSONUtils.prettyPrintJSON;

/**
 * Presenter for the Keys tab
 */
public class KeysPresenter {

    private final KeysModel model;
    private final KeysView view;
    private final KeysDialogFactory keysDialogFactory;

    public KeysPresenter(KeysView view,
                         KeysModelPersistence keysModelPersistence,
                         KeysModel keysModel,
                         KeysDialogFactory keysDialogFactory) {
        this.view = view;
        this.model = keysModel;
        this.keysDialogFactory = keysDialogFactory;

        model.addKeyModelListener(new KeysModelListener() {
            @Override
            public void notifyKeyInserted(Key key) {
                view.addKey(key);
                keysModelPersistence.save(keysModel);
            }

            @Override
            public void notifyKeyDeleted(Key key) {
                if (key != null) {
                    view.deleteKey(key);
                    keysModelPersistence.save(keysModel);
                }
            }

            @Override
            public void notifyKeyDeleted(int rowIndex) {
                view.deleteKey(rowIndex);
                keysModelPersistence.save(keysModel);
            }
        });
    }

    /**
     * Handler for double-click events from the keys view
     */
    public void onTableKeysDoubleClick() {
        Key key = model.getKey(view.getSelectedRow());
        KeyDialog dialog = keysDialogFactory.dialogFor(key);

        if (dialog == null) {
            return;
        }

        dialog.display();

        // If dialog returned a key, replace the key in the store with the new key
        Key newKey = dialog.getKey();

        if (newKey != null) {
            model.deleteKey(key.getID());
            model.addKey(dialog.getKey());
        }
    }

    private void onButtonNewClicked(KeyDialog d) {
        d.display();

        // If the dialog returned a key, add it to the model
        if (d.getKey() != null) {
            model.addKey(d.getKey());
        }
    }

    /**
     * Handler for button clicks for new symmetric keys
     */
    public void onButtonNewSymmetricClick() {
        onButtonNewClicked(keysDialogFactory.symmetricKeyDialog());
    }

    /**
     * Handler for button clicks for new RSA keys
     */
    public void onButtonNewRSAClick() {
        onButtonNewClicked(keysDialogFactory.rsaKeyDialog());
    }

    /**
     * Handler for button clicks for new EC keys
     */
    public void onButtonNewECClick() {
        onButtonNewClicked(keysDialogFactory.ecKeyDialog());
    }

    /**
     * Handler for button clicks for new OKPs
     */
    public void onButtonNewOKPClick() {
        onButtonNewClicked(keysDialogFactory.okpDialog());
    }

    /**
     * Handler for button clicks for new passwords
     */
    public void onButtonNewPasswordClick() {
        onButtonNewClicked(keysDialogFactory.passwordDialog());
    }

    /**
     * Can the key at a position in the model be copied as a JWK with private key
     *
     * @param row the index of the key to be copied from the position in the view
     * @return true if the key is a JWK with private key
     */
    public boolean canCopyJWK(int row) {
        Key key = model.getKey(row);
        return key.hasJWK() && key.isPrivate();
    }

    /**
     * Can the key at a position in the model be copied as a private key PEM
     *
     * @param row the index of the key to be copied from the position in the view
     * @return true if the key has a private key and can be formatted as a PEM
     */
    public boolean canCopyPEM(int row) {
        Key key = model.getKey(row);
        return key.hasPEM() && key.isPrivate();
    }

    /**
     * Can the key at a position in the model be copied as a public key JWK
     *
     * @param row the index of the key to be copied from the position in the view
     * @return true if the key has a public key and can be formatted as a JWK
     */
    public boolean canCopyPublicJWK(int row) {
        Key key = model.getKey(row);
        return key.hasJWK() && key.isPublic();
    }

    /**
     * Can the key at a position in the model be copied as a public key PEM
     *
     * @param row the index of the key to be copied from the position in the view
     * @return true if the key has a public key and can be formatted as a PEM
     */
    public boolean canCopyPublicPEM(int row) {
        Key key = model.getKey(row);
        return key.hasPEM() && key.isPublic();
    }

    /**
     * Can the key at a position in the model be copied as a password
     *
     * @param row the index of the key to be copied from the position in the view
     * @return true if the key is a password
     */
    public boolean canCopyPassword(int row) {
        Key key = model.getKey(row);
        return key instanceof PasswordKey;
    }

    public boolean canCopyJWKSet(int[] rows) {
        return IntStream.of(rows)
                .mapToObj(model::getKey)
                .filter(Objects::nonNull)
                .anyMatch(Key::hasJWK);
    }

    /**
     * Handle click events on the row delete popup
     *
     * @param rows array of indices of the keys to be deleted from the position in the view
     */
    public void onPopupDelete(int[] rows) {
        String messageResourceId = rows.length > 1 ? "keys_confirm_delete_multiple" : "keys_confirm_delete_single";

        int option = JOptionPane.showConfirmDialog(
                view.getParent(),
                Utils.getResourceString(messageResourceId),
                Utils.getResourceString("keys_confirm_delete_title"),
                JOptionPane.YES_NO_OPTION
        );

        if (option == JOptionPane.OK_OPTION) {
            model.deleteKeys(rows);
        }
    }

    /**
     * Handle click events on the copy JWK popup menu entry
     *
     * @param row the index of the key from the position in the view
     */
    public void onPopupCopyJWK(int row) {
        JWKKey jwkKey = (JWKKey) model.getKey(row);
        JWK jwk = jwkKey.getJWK();
        Utils.copyToClipboard(prettyPrintJSON(jwk.toJSONString()));
    }

    /**
     * Handle click events on the copy PEM popup menu entry
     *
     * @param row the index of the key from the position in the view
     */
    public void onPopupCopyPEM(int row) {
        JWKKey jwkKey = (JWKKey) model.getKey(row);
        JWK jwk = jwkKey.getJWK();
        try {
            Utils.copyToClipboard(PEMUtils.jwkToPem(jwk));
        } catch (PemException e) {
            throw new IllegalStateException("Shouldn't happen - call canCopyPEM first");
        }
    }

    /**
     * Handle click events on the copy public JWK popup menu entry
     *
     * @param row the index of the key from the position in the view
     */
    public void onPopupCopyPublicJWK(int row) {
        JWKKey jwkKey = (JWKKey) model.getKey(row);
        JWK jwk = jwkKey.getJWK().toPublicJWK();
        Utils.copyToClipboard(prettyPrintJSON(jwk.toJSONString()));
    }

    /**
     * Handle click events on the copy public PEM popup menu entry
     *
     * @param row the index of the key from the position in the view
     */
    public void onPopupCopyPublicPEM(int row) {
        JWKKey jwkKey = (JWKKey) model.getKey(row);
        JWK jwk = jwkKey.getJWK().toPublicJWK();
        try {
            Utils.copyToClipboard(PEMUtils.jwkToPem(jwk));
        } catch (PemException e) {
            throw new IllegalStateException("Shouldn't happen - call canCopyPEM first");
        }
    }

    /**
     * Handle click events on the copy password popup menu entry
     *
     * @param row the index of the key from the position in the view
     */
    public void onPopupCopyPassword(int row) {
        PasswordKey passwordKey = (PasswordKey) model.getKey(row);
        Utils.copyToClipboard(passwordKey.getPassword());
    }

    public void onPopupJWKSet(int[] rows) {
        List<JWK> selectedJwk = IntStream.of(rows)
                .mapToObj(model::getKey)
                .filter(Objects::nonNull)
                .filter(key -> key instanceof JWKKey)
                .map(key -> ((JWKKey) key).getJWK())
                .toList();

        JWKSet jwkSet = new JWKSet(selectedJwk);
        String jwkSetJson = jwkSet.serialize();

        Utils.copyToClipboard(jwkSetJson);
    }
}
