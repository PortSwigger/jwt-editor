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

package com.blackberry.jwteditor.view.dialog.keys;

import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.model.keys.KeysModel;
import com.blackberry.jwteditor.model.keys.PasswordKey;
import com.blackberry.jwteditor.view.rsta.RstaFactory;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

import java.awt.*;

public class KeysDialogFactory {
    private final KeysModel model;
    private final RstaFactory rstaFactory;
    private final AsymmetricKeyDialogFactory asymmetricKeyDialogFactory;
    private final Window window;

    public KeysDialogFactory(KeysModel model, RstaFactory rstaFactory, Window window) {
        this.model = model;
        this.rstaFactory = rstaFactory;
        this.window = window;
        this.asymmetricKeyDialogFactory = new AsymmetricKeyDialogFactory(window, model, rstaFactory);
    }

    public KeyDialog dialogFor(Key key) {
        if (key instanceof JWKKey jwkKey) {
            return switch (jwkKey.getJWK()) {
                case RSAKey rsaKey -> asymmetricKeyDialogFactory.rsaKeyDialog(rsaKey);
                case ECKey ecKey -> asymmetricKeyDialogFactory.ecKeyDialog(ecKey);
                case OctetKeyPair octetKeyPair -> asymmetricKeyDialogFactory.okpDialog(octetKeyPair);
                case OctetSequenceKey octetSequenceKey -> new SymmetricKeyDialog(window, model, rstaFactory, octetSequenceKey);
                default -> null;
            };
        }

        if (key instanceof PasswordKey passwordKey) {
            return new PasswordDialog(window, model, passwordKey);
        }

        return null;
    }

    public KeyDialog rsaKeyDialog() {
        return asymmetricKeyDialogFactory.rsaKeyDialog();
    }

    public KeyDialog ecKeyDialog() {
        return asymmetricKeyDialogFactory.ecKeyDialog();
    }

    public KeyDialog okpDialog() {
        return asymmetricKeyDialogFactory.okpDialog();
    }

    public KeyDialog passwordDialog() {
        return new PasswordDialog(window, model);
    }

    public KeyDialog symmetricKeyDialog() {
        return new SymmetricKeyDialog(window, model, rstaFactory, null);
    }
}
