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

package com.blackberry.jwteditor;

import com.blackberry.jwteditor.exceptions.PemException;
import com.blackberry.jwteditor.exceptions.UnsupportedKeyException;
import com.blackberry.jwteditor.model.keys.JWKKeyFactory;
import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.model.keys.KeyRing;
import com.blackberry.jwteditor.utils.PEMUtils;
import com.nimbusds.jose.jwk.JWK;

import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

class KeysRingBuilder {
    private final AtomicInteger keyId = new AtomicInteger();
    private final List<Key> keys = new LinkedList<>();

    KeysRingBuilder withECKey(String pem) {
        try {
            JWK jwk = PEMUtils.pemToECKey(pem, Integer.toString(keyId.incrementAndGet()));
            keys.add(JWKKeyFactory.from(jwk));
        } catch (PemException | UnsupportedKeyException e) {
            throw new IllegalStateException(e);
        }

        return this;
    }

    KeysRingBuilder withRSAKey(String pem) {
        try {
            JWK jwk = PEMUtils.pemToRSAKey(pem, Integer.toString(keyId.incrementAndGet()));
            keys.add(JWKKeyFactory.from(jwk));
        } catch (PemException | UnsupportedKeyException e) {
            throw new IllegalStateException(e);
        }

        return this;
    }

    KeysRingBuilder withOKPKey(String pem) {
        try {
            JWK jwk = PEMUtils.pemToOctetKeyPair(pem, Integer.toString(keyId.incrementAndGet()));
            keys.add(JWKKeyFactory.from(jwk));
        } catch (PemException | UnsupportedKeyException e) {
            throw new IllegalStateException(e);
        }

        return this;
    }

    KeyRing build() {
        return new KeyRing(keys);
    }

    static KeysRingBuilder keyRing() {
        return new KeysRingBuilder();
    }
}
