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

class JsonData {
    static final String PRETTY_PRINTED_JSON = """
            {
                "kid": "dfc6a9df-916c-406d-84de-ce5b49d50ad0",
                "typ": "JWT",
                "alg": "RS256",
                "jwk": {
                    "kty": "RSA",
                    "e": "AQAB",
                    "kid": "dfc6a9df-916c-406d-84de-ce5b49d50ad0",
                    "n": "p0U0MdHFLPovX5j91oH-dc54oeJDIDapuPDM9gYHjhX2Bwj4fFhqvaAfIhn-w7zm-6HZsH-VxPCngl7GkWxx1F7Cobkg8TOD4UusFFo8srSFDExWCQ4MRFDRcLN9bmfXeiR-MvGE1tHZNJCOnxsx32-ueF0T2xo880-073skum8sS9vi7RuNhaCY_liJNkrznqQCEbNLR_-V_-IQaFG_obDNqEHroKC3lxz34s4CPpUwen8IFJm8_vbcFiI_jZrw_VTwJM4Il5Hr2uJLv_ahsZTLomumJmabvXulgQFBK4hEd-FH4c72glbFfFLEkzRQz-ozCzySudbRG9UvhubPyQ"
                }
            }""";

    static final String COMPACTED_JSON = "{\"kid\":\"dfc6a9df-916c-406d-84de-ce5b49d50ad0\",\"typ\":\"JWT\",\"alg\":\"RS256\",\"jwk\":{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"dfc6a9df-916c-406d-84de-ce5b49d50ad0\",\"n\":\"p0U0MdHFLPovX5j91oH-dc54oeJDIDapuPDM9gYHjhX2Bwj4fFhqvaAfIhn-w7zm-6HZsH-VxPCngl7GkWxx1F7Cobkg8TOD4UusFFo8srSFDExWCQ4MRFDRcLN9bmfXeiR-MvGE1tHZNJCOnxsx32-ueF0T2xo880-073skum8sS9vi7RuNhaCY_liJNkrznqQCEbNLR_-V_-IQaFG_obDNqEHroKC3lxz34s4CPpUwen8IFJm8_vbcFiI_jZrw_VTwJM4Il5Hr2uJLv_ahsZTLomumJmabvXulgQFBK4hEd-FH4c72glbFfFLEkzRQz-ozCzySudbRG9UvhubPyQ\"}}";

    static final String INVALID_JSON = """
            {
                "kid": "dfc6a9df-916c-406d-84de-ce5b49d50ad0",
                "typ": "JWT"
            """;
}
