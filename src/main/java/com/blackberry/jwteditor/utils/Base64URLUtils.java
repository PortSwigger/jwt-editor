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

package com.blackberry.jwteditor.utils;

import com.nimbusds.jose.util.Base64URL;
import org.json.JSONException;

import static com.blackberry.jwteditor.utils.JSONUtils.compactJSON;

public class Base64URLUtils {
    public static Base64URL base64UrlEncodeJson(String json, boolean compactJson) {
        try {
            return compactJson ? Base64URL.encode(compactJSON(json)) : Base64URL.encode(json);
        } catch (JSONException e) {
            return Base64URL.encode(json);
        }
    }
}
