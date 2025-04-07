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

package com.blackberry.jwteditor.view.dialog.operations;

import com.blackberry.jwteditor.model.jose.JWS;

import java.awt.*;

abstract class SingleFixedInputJWSOperation<T> extends OperationPanel<JWS, JWS> {
    private final SingleComboBoxPanel<T> panel;

    SingleFixedInputJWSOperation(String dialogTitleId, String inputTitleId, T[] options) {
        super(dialogTitleId);
        this.panel = new SingleComboBoxPanel<>(inputTitleId, options);
        add(panel, BorderLayout.CENTER);
    }

    T selectedInputValue() {
        return panel.selectedItem();
    }
}
