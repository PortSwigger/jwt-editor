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

package com.blackberry.jwteditor.model.keys;

import com.blackberry.jwteditor.exceptions.UnsupportedKeyException;
import com.nimbusds.jose.jwk.JWKSet;

import java.text.ParseException;
import java.util.List;
import java.util.Objects;

public class JWKSetParser {
    public List<Key> parse(String json) throws ParseException {
        return JWKSet.parse(json)
                .getKeys()
                .stream()
                .map(jwk -> {
                    try {
                        return JWKKeyFactory.from(jwk);
                    } catch (UnsupportedKeyException e) {
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .map(key -> (Key) key)
                .toList();
    }
}
