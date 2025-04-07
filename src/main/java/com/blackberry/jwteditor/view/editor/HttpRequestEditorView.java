/*
Author : Dolph Flynn

Copyright 2022 Dolph Flynn

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
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.blackberry.jwteditor.model.keys.KeysRepository;
import com.blackberry.jwteditor.model.tokens.TokenIdGenerator;
import com.blackberry.jwteditor.model.tokens.TokenRepository;
import com.blackberry.jwteditor.view.hexcodearea.HexCodeAreaFactory;
import com.blackberry.jwteditor.view.rsta.RstaFactory;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;
import static com.blackberry.jwteditor.model.jose.JOSEObjectFinder.containsJOSEObjects;

public class HttpRequestEditorView extends HttpEditorView implements ExtensionProvidedHttpRequestEditor {

    public HttpRequestEditorView(
            KeysRepository keysRepository,
            TokenRepository tokenRepository,
            TokenIdGenerator tokenIdGenerator,
            RstaFactory rstaFactory,
            CollaboratorPayloadGenerator collaboratorPayloadGenerator,
            HexCodeAreaFactory hexAreaCodeFactory,
            Logging logging,
            InformationPanelFactory informationPanelFactory,
            boolean editable,
            boolean isProVersion) {
        super(
                keysRepository,
                tokenRepository,
                tokenIdGenerator,
                rstaFactory,
                hexAreaCodeFactory,
                collaboratorPayloadGenerator,
                logging,
                informationPanelFactory,
                editable,
                isProVersion
        );
    }

    @Override
    void setMessage(HttpRequestResponse requestResponse) {
        HttpRequest httpRequest = requestResponse.request();
        presenter.setMessage(httpRequest.toByteArray().toString());
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        String content = requestResponse.request().toByteArray().toString();
        return containsJOSEObjects(content);
    }

    @Override
    public HttpRequest getRequest() {
        return FACTORY.httpRequest(httpService, presenter.getMessage());
    }
}
