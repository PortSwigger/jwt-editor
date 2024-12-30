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

package com.blackberry.jwteditor.model.jose;

import com.blackberry.jwteditor.exceptions.SigningException;
import com.blackberry.jwteditor.model.keys.Key;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import org.json.JSONException;
import org.json.JSONObject;

import java.text.ParseException;

import static com.blackberry.jwteditor.utils.StringUtils.countOccurrences;
import static com.nimbusds.jose.HeaderParameterNames.*;
import static java.util.Arrays.stream;

public class JWSFactory {
    public enum SigningUpdateMode {
        DO_NOT_MODIFY_HEADER,
        UPDATE_ALGORITHM_ONLY,
        UPDATE_ALGORITHM_TYPE_AND_KID;

        Base64URL buildUpdatedHeader(JWS jws, Key key, JWSAlgorithm algorithm) {
            return switch (this) {
                case DO_NOT_MODIFY_HEADER -> jws.header().encoded();

                case UPDATE_ALGORITHM_ONLY -> {
                    JSONObject jsonHeader = parseHeader(jws);
                    jsonHeader.put(ALGORITHM, algorithm.getName());

                    yield Base64URL.encode(jsonHeader.toString());
                }

                case UPDATE_ALGORITHM_TYPE_AND_KID -> {
                    JSONObject jsonHeader = parseHeader(jws);
                    jsonHeader.put(ALGORITHM, algorithm.getName());
                    jsonHeader.put(TYPE, "JWT");
                    jsonHeader.put(KEY_ID, key.getID());

                    yield Base64URL.encode(jsonHeader.toString());
                }
            };
        }

        private static JSONObject parseHeader(JWS jws) {
            try {
                return jws.header().json();
            } catch (JSONException e) {
                return new JSONObject();
            }
        }
    }

    public static JWS sign(Key key, Base64URL header, Base64URL payload, JWSHeader signingInfo) throws SigningException {
       return sign(key, signingInfo.getAlgorithm(), header, payload);
    }

    public static JWS sign(Key key, JWSAlgorithm algorithm, SigningUpdateMode updateMode, JWS jws) throws SigningException {
        return sign(
                key,
                algorithm,
                updateMode.buildUpdatedHeader(jws, key, algorithm),
                jws.claims().encoded()
        );
    }

    public static JWS sign(Key key, JWSAlgorithm algorithm, Base64URL header, Base64URL payload) throws SigningException {
        return new JWSSigner(key).sign(header, payload, new JWSHeader.Builder(algorithm).build());
    }

    /**
     * Parse a JWS from compact serialization
     *
     * @param compactJWS the JWS in compact serialization
     * @return the parsed JWS
     * @throws ParseException if parsing fails
     */
    public static JWS parse(String compactJWS) throws ParseException {
        if (countOccurrences(compactJWS, '.') != 2) {
            throw new ParseException("Invalid number of encoded sections", 0);
        }

        Base64URL[] parts = com.nimbusds.jose.JOSEObject.split(compactJWS);

        boolean allEmpty = stream(parts).allMatch(part -> part.decodeToString().isEmpty());

        if (allEmpty) {
            throw new ParseException("All sections empty", 0);
        }

        return new JWS(parts[0], parts[1], parts[2]);
    }

    /**
     * Construct a JWS from encoded components
     * @param header the encoded header
     * @param payload the encoded payload
     * @param signature the encoded signature
     */
    public static JWS jwsFromParts(Base64URL header, Base64URL payload, Base64URL signature) {
        return new JWS(header, payload, signature);
    }
}
