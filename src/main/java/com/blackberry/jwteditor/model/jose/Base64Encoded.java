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

public abstract class Base64Encoded {
    private final Base64URL data;

    Base64Encoded(Base64URL data) {
        this.data = data;
    }

    public Base64URL encoded() {
        return data;
    }

    public String decoded() {
        return data.decodeToString();
    }

    @Override
    public String toString() {
        return data.toString();
    }
}
