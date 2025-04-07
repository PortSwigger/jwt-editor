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
import org.json.JSONObject;

import static com.blackberry.jwteditor.utils.JSONUtils.isJsonCompact;
import static com.blackberry.jwteditor.utils.JSONUtils.prettyPrintJSON;
import static com.nimbusds.jose.HeaderParameterNames.ALGORITHM;
import static com.nimbusds.jose.HeaderParameterNames.KEY_ID;

public class Header extends Base64Encoded {

    public Header(Base64URL header) {
        super(header);
    }

    public boolean isCompact() {
        return isJsonCompact(decoded());
    }

    public String decodeAndPrettyPrint() {
        return prettyPrintJSON(decoded());
    }

    public JSONObject json() {
        return new JSONObject(decoded());
    }

    public String algorithm() {
        return headerValue(ALGORITHM);
    }

    public String keyId() {
        return headerValue(KEY_ID);
    }

    private String headerValue(String key) {
        JSONObject json = json();
        return json.has(key) ? json.getString(key) : "";
    }
}
