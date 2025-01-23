/*

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
import com.blackberry.jwteditor.utils.Utils;

import static java.awt.event.KeyEvent.*;

public enum Attack {
    EmbedJWK("editor_view_button_attack_embed_jwk", VK_J),
    SignNone("editor_view_button_attack_sign_none", VK_N),
    KeyConfusion("editor_view_button_attack_key_confusion", VK_H),
    SignEmptyKey("editor_view_button_attack_sign_empty_key", VK_E),
    SignPsychicSignature("editor_view_button_attack_sign_psychic_signature", VK_P),
    EmbedCollaboratorPayload("editor_view_button_attack_embed_collaborator_payload", VK_C),
    WeakSymmetricKey("editor_view_button_attack_weak_symmetric_key", VK_W);

    private final String labelResourceId;
    private final int mnemonic;

    Attack(String labelResourceId, int mnemonic) {
        this.labelResourceId = labelResourceId;
        this.mnemonic = mnemonic;
    }

    String label() {
        return Utils.getResourceString(labelResourceId);
    }

    boolean isProOnly() {
        return switch (this) {
            case EmbedCollaboratorPayload -> true;
            default -> false;
        };
    }

    int mnemonic() {
        return mnemonic;
    }

    void performOperation(EditorPresenter presenter) {
        switch (this) {
            case EmbedJWK -> presenter.onAttackEmbedJWKClicked();
            case SignNone -> presenter.onAttackSignNoneClicked();
            case KeyConfusion -> presenter.onAttackKeyConfusionClicked();
            case SignEmptyKey -> presenter.onAttackSignEmptyKeyClicked();
            case SignPsychicSignature -> presenter.onAttackPsychicSignatureClicked();
            case EmbedCollaboratorPayload -> presenter.onAttackEmbedCollaboratorPayloadClicked();
            case WeakSymmetricKey -> presenter.onAttackWeakHMACSecret();
        }
    }
}
