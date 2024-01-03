/*
Author : Dolph Flynn

Copyright 2023 Dolph Flynn

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

import com.blackberry.jwteditor.presenter.PresenterStore;
import com.blackberry.jwteditor.view.rsta.RstaFactory;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;

import java.awt.*;

import static com.blackberry.jwteditor.view.dialog.keys.AsymmetricKeyDialogMode.*;

public class AsymmetricKeyDialogFactory {
    private final Window parent;
    private final PresenterStore presenters;
    private final RstaFactory rstaFactory;

    public AsymmetricKeyDialogFactory(Window parent, PresenterStore presenters, RstaFactory rstaFactory) {
        this.parent = parent;
        this.presenters = presenters;
        this.rstaFactory = rstaFactory;
    }

    public AsymmetricKeyDialog rsaKeyDialog() {
        return rsaKeyDialog(null);
    }

    public AsymmetricKeyDialog rsaKeyDialog(RSAKey rsaKey) {
        return new AsymmetricKeyDialog(
                parent,
                presenters,
                rstaFactory,
                RSA,
                rsaKey
        );
    }

    public AsymmetricKeyDialog ecKeyDialog() {
        return ecKeyDialog(null);
    }

    public AsymmetricKeyDialog ecKeyDialog(ECKey ecKey) {
        return new AsymmetricKeyDialog(
                parent,
                presenters,
                rstaFactory,
                EC,
                ecKey
        );
    }

    public AsymmetricKeyDialog okpDialog() {
        return okpDialog(null);
    }

    public AsymmetricKeyDialog okpDialog(OctetKeyPair octetKeyPair) {
        return new AsymmetricKeyDialog(
                parent,
                presenters,
                rstaFactory,
                OKP,
                octetKeyPair
        );
    }
}
