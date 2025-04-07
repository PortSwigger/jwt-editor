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

package com.blackberry.jwteditor.model.tokens;

import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.jose.JWSClaims;

import static com.blackberry.jwteditor.model.jose.ClaimsType.JSON;
import static com.blackberry.jwteditor.utils.JSONUtils.prettyPrintJSON;

public class Token {
    private final int id;
    private final String host;
    private final String path;
    private final JWS jws;

    public Token(int id, String host, String path, JWS jws) {
        this.host = host;
        this.path = path;
        this.jws = jws;
        this.id = id;
    }

    public int id() {
        return id;
    }

    public String host() {
        return host;
    }

    public String path() {
        return path;
    }

    public String algorithm() {
        return jws.header().algorithm();
    }

    public String keyId() {
        return jws.header().keyId();
    }

    public String jws() {
        return jws.serialize();
    }

    public String claims() {
        JWSClaims claims = jws.claims();
        String decodedClaim = claims.decoded();

        return claims.type() == JSON ? prettyPrintJSON(decodedClaim) : decodedClaim;
    }
}
