/*
Author : Dolph Flynn

Copyright 2022 Dolph Flynn

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

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;

import java.text.ParseException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.nimbusds.jose.Header.MAX_HEADER_STRING_LENGTH;
import static com.nimbusds.jose.HeaderParameterNames.ALGORITHM;

public class JOSEObjectFinder {
    public static final String BASE64_REGEX = "[A-Za-z0-9-_]";

    private static final String JWS_REGEX = "e%s*\\.%s+\\.%s*".formatted(BASE64_REGEX, BASE64_REGEX, BASE64_REGEX);
    private static final String JWE_REGEX = "e%s*\\.%s*\\.%s+\\.%s+\\.%s+".formatted(BASE64_REGEX, BASE64_REGEX, BASE64_REGEX, BASE64_REGEX, BASE64_REGEX);
    private static final Pattern JOSE_OBJECT_PATTERN = Pattern.compile("(%s)|(%s)".formatted(JWE_REGEX, JWS_REGEX));

    /**
     * Extract a list of JOSEObjectPairs from a block of text that may contain JWE/JWS in compact form
     *
     * @param text text block
     * @return list of JOSEObjectPairs
     */
    public static List<MutableJOSEObject> extractJOSEObjects(String text) {
        List<MutableJOSEObject> joseObjects = new ArrayList<>();

        Set<String> candidates = findCandidateJoseObjectsWithin(text);

        for (String candidate : candidates) {
            parseJWT(candidate).ifPresent(value -> joseObjects.add(new MutableJOSEObject(candidate, value)));
        }

        return joseObjects;
    }

    public static boolean containsJOSEObjects(String text) {
        Set<String> candidates = findCandidateJoseObjectsWithin(text);

        for (String candidate : candidates) {
            // Try to parse each as both a JWE and a JWS
            Optional<JOSEObject> jwe = parseJWE(candidate);
            Optional<JOSEObject> jws = jwe.isEmpty() ? parseJWS(candidate) : Optional.empty();

            if (jwe.isPresent() || jws.isPresent()) {
                return true;
            }
        }

        return false;
    }

    public static Optional<JOSEObject> parseJOSEObject(String text) {
        return parseJWT(text);
    }

    private static Set<String> findCandidateJoseObjectsWithin(String text) {
        Matcher m = JOSE_OBJECT_PATTERN.matcher(text);
        Set<String> strings = new LinkedHashSet<>();

        while (m.find()) {
            String token = m.group();
            strings.add(token);
        }

        return strings;
    }

    private static Optional<JOSEObject> parseJWT(String candidate) {
        Matcher m = JOSE_OBJECT_PATTERN.matcher(candidate);

        if (!m.matches()) {
            return Optional.empty();
        }

        // Try to parse each as both a JWE and a JWS
        Optional<JOSEObject> jwe = parseJWE(candidate);
        return jwe.isPresent() ? jwe : parseJWS(candidate);
    }

    private static Optional<JOSEObject> parseJWE(String candidate) {
        try {
            JWEObject.parse(candidate);
            return Optional.of(JWEFactory.parse(candidate));
        } catch (ParseException e) {
            return Optional.empty();
        }
    }

    private static Optional<JOSEObject> parseJWS(String candidate) {
        try {
            Base64URL[] parts = com.nimbusds.jose.JOSEObject.split(candidate);

            if (parts.length != 3) {
                throw new ParseException("Unexpected number of Base64URL parts, must be three", 0);
            }

            // Header must be Base64URL encoded UTF-8 encoded JSON object with 'alg' value
            Base64URL encodedHeader = parts[0];
            String header = encodedHeader.decodeToString(); // assumes UTF-8
            Map<String, Object> headerJson = JSONObjectUtils.parse(header, MAX_HEADER_STRING_LENGTH);

            String algValue = JSONObjectUtils.getString(headerJson, ALGORITHM);

            if (algValue == null || algValue.isBlank()) {
                throw new ParseException("Missing \"alg\" in header JSON object", 0);
            }

            // Payload must be Base64URL encoded UTF-8 encoded JSON object
            Base64URL encodedPayload = parts[1];
            String payload = encodedPayload.decodeToString();
            JSONObjectUtils.parse(payload); // throws ParseException if not JSON object

            return Optional.of(JWSFactory.parse(candidate));
        } catch (ParseException e) {
            return Optional.empty();
        }
    }
}
