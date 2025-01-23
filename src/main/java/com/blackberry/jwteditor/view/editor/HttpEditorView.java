/*
Author : Dolph Flynn

Copyright 2024 Dolph Flynn

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

import burp.api.montoya.collaborator.CollaboratorPayloadGenerator;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedEditor;
import com.blackberry.jwteditor.model.keys.KeysRepository;
import com.blackberry.jwteditor.view.hexcodearea.HexCodeAreaFactory;
import com.blackberry.jwteditor.view.rsta.RstaFactory;

abstract class HttpEditorView extends EditorView implements ExtensionProvidedEditor {

    HttpEditorView(
            KeysRepository keysRepository,
            RstaFactory rstaFactory,
            HexCodeAreaFactory hexAreaCodeFactory,
            CollaboratorPayloadGenerator collaboratorPayloadGenerator,
            Logging logging,
            InformationPanelFactory informationPanelFactory,
            boolean editable,
            boolean isProVersion) {
        super(
                keysRepository,
                rstaFactory,
                hexAreaCodeFactory,
                collaboratorPayloadGenerator,
                logging,
                informationPanelFactory,
                editable,
                isProVersion
        );
    }
}
