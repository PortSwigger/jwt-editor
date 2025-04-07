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

package com.blackberry.jwteditor.view.editor;

import com.blackberry.jwteditor.presenter.EditorPresenter;

import javax.swing.*;

class EditorViewAttackMenuFactory {
    private final EditorPresenter presenter;
    private final boolean isProVersion;

    EditorViewAttackMenuFactory(EditorPresenter presenter, boolean isProVersion) {
        this.presenter = presenter;
        this.isProVersion = isProVersion;
    }

    JPopupMenu buildAttackPopupMenu() {
        JPopupMenu popupMenuAttack = new JPopupMenu();

        for (Attack attack : Attack.values()) {
            JMenuItem item = new JMenuItem(attack.label(), attack.mnemonic());
            item.addActionListener(e -> presenter.perform(attack));

            if (attack.isProOnly()) {
                item.setEnabled(isProVersion);
            }

            popupMenuAttack.add(item);
        }

        return popupMenuAttack;
    }
}
