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
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;
import com.blackberry.jwteditor.presenter.PresenterStore;
import com.blackberry.jwteditor.view.hexcodearea.HexCodeAreaFactory;
import com.blackberry.jwteditor.view.rsta.RstaFactory;
import com.blackberry.jwteditor.view.utils.ErrorLoggingActionListenerFactory;

public class WebSocketEditorView extends EditorView implements ExtensionProvidedWebSocketMessageEditor {

    public WebSocketEditorView(PresenterStore presenters,
                               RstaFactory rstaFactory,
                               Logging logging,
                               UserInterface userInterface,
                               CollaboratorPayloadGenerator collaboratorPayloadGenerator,
                               boolean editable,
                               boolean isProVersion) {
        super(
                presenters,
                rstaFactory,
                new HexCodeAreaFactory(logging, userInterface),
                collaboratorPayloadGenerator,
                new ErrorLoggingActionListenerFactory(logging),
                new InformationPanelFactory(userInterface, logging),
                editable,
                isProVersion
        );
    }

    @Override
    public ByteArray getMessage() {
        return ByteArray.byteArray(presenter.getMessage());
    }

    @Override
    public void setMessage(WebSocketMessage message) {
        presenter.setMessage(message.payload().toString());
    }

    @Override
    public boolean isEnabledFor(WebSocketMessage message) {
        String content = message.payload().toString();
        return presenter.isEnabled(content);
    }
}
