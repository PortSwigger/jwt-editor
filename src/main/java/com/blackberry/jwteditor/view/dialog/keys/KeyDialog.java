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

import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.presenter.KeysPresenter;
import com.blackberry.jwteditor.presenter.PresenterStore;
import com.blackberry.jwteditor.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import static javax.swing.JOptionPane.*;

/**
 * Abstract class to be extended by dialogs for key editing/generation on the Keys tab
 */
public abstract class KeyDialog extends JDialog {
    private final String originalId;
    private final PresenterStore presenters;

    public KeyDialog(Window parent, String titleResourceId, String originalId, PresenterStore presenters) {
        super(parent);

        this.originalId = originalId;
        this.presenters = presenters;

        setModal(true);
        setTitle(Utils.getResourceString(titleResourceId));

        // call onCancel() when cross is clicked
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                onCancel();
            }
        });
    }

    /**
     * Get the key generated/edited by the dialog
     *
     * @return the new/modified key
     */
    public abstract Key getKey();

    abstract void onCancel();

    public void display() {
        pack();
        setLocationRelativeTo(getOwner());
        setVisible(true);
    }

    /**
     * Handler for OK button click
     */
    void onOK() {
        KeysPresenter keyPresenter = (KeysPresenter) presenters.get(KeysPresenter.class);
        Key newKey = getKey();

        boolean checkForKeyIdClash = originalId == null || !newKey.getID().equals(originalId);

        // Handle overwrites if a key already exists with the same kid
        if (checkForKeyIdClash && keyPresenter.keyExists(newKey.getID())) {
            if (showConfirmDialog(
                    this,
                    Utils.getResourceString("keys_confirm_overwrite"),
                    Utils.getResourceString("keys_confirm_overwrite_title"),
                    OK_CANCEL_OPTION) != OK_OPTION) {
                return;
            }
        }

        dispose();
    }
}
