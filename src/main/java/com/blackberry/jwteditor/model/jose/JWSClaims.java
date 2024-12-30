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

package com.blackberry.jwteditor.model.jose;

import com.nimbusds.jose.util.Base64URL;

import java.util.List;

import static com.blackberry.jwteditor.model.jose.ClaimsType.JSON;
import static com.blackberry.jwteditor.model.jose.ClaimsType.TEXT;
import static com.blackberry.jwteditor.utils.JSONUtils.isJsonObject;
import static java.util.Collections.emptyList;

public class JWSClaims extends Base64Encoded {
    private final ClaimsType type;
    private final List<TimeClaim> timeClaims;

    public JWSClaims(Base64URL encodedClaims) {
        super(encodedClaims);

        this.type = isJsonObject(encodedClaims.decodeToString()) ? JSON : TEXT;
        this.timeClaims = type == JSON
                ? TimeClaimFactory.fromPayloadJson(encodedClaims.decodeToString())
                : emptyList();
    }

    public ClaimsType type() {
        return type;
    }

    public List<TimeClaim> timeClaims() {
        return timeClaims;
    }
}
