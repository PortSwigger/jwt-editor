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

package com.blackberry.jwteditor.utils;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class JSONUtils {
    private static final int JSON_INDENTATION = 4;

    /**
     * Pretty print a string containing JSON using standard indentation
     *
     * @param json String containing JSON to pretty print
     * @return String containing pretty printed JSON
     */
    public static String prettyPrintJSON(String json) {
        // Strip any whitespace from the JSON string, also ensures the string actually contains valid JSON
        json = compactJSON(json);

        StringBuilder stringBuilder = new StringBuilder();

        // Simple pretty printer that increases indentation for every new Object or Array and places each key/value pair on a new line
        int indentationLevel = 0;
        boolean stringContext = false;

        for (char c : json.toCharArray()) {

            if (stringContext) {
                stringBuilder.append(c);
            } else {
                switch (c) {
                    case '{':
                    case '[':
                        indentationLevel++;
                        stringBuilder.append(c);
                        stringBuilder.append('\n');
                        stringBuilder.append(" ".repeat( indentationLevel * JSON_INDENTATION));
                        break;

                    case '}':
                    case ']':
                        indentationLevel--;
                        stringBuilder.append('\n');
                        stringBuilder.append(" ".repeat(indentationLevel * JSON_INDENTATION));
                        stringBuilder.append(c);
                        break;

                    case ':':
                        stringBuilder.append(": ");
                        break;

                    case ',':
                        stringBuilder.append(",\n");
                        stringBuilder.append(" ".repeat(indentationLevel * JSON_INDENTATION));
                        break;

                    default:
                        stringBuilder.append(c);
                        break;
                }
            }

            if (c == '"') {
                stringContext = !stringContext;
            }
        }

        return stringBuilder.toString();
    }

    /**
     * Strip the whitespace from a string containing JSON
     *
     * @param json JSON string containing whitespace
     * @return JSON string without whitespace
     */
    public static String compactJSON(String json) {

        // Use JSONObject or JSONArray to perform an initial parse to check the content of the string is JSON
        try {
            new JSONObject(json);
        } catch (JSONException e) {
            try {
                new JSONArray(json);
            } catch (JSONException e2) {
                throw e;
            }
        }

        StringBuilder stringBuilder = new StringBuilder();
        // Whitespace in JSON is four characters that are not inside a matched pair of double quotes
        boolean stringContext = false;
        for (char c : json.toCharArray()) {
            if (!stringContext && (c == 0x20 || c == 0x0A || c == 0x0D || c == 0x09)) {
                continue;
            }

            stringBuilder.append(c);

            if (c == '"') {
                stringContext = !stringContext;
            }
        }

        return stringBuilder.toString();
    }

    public static boolean isJsonCompact(String json) {
        try {
            return compactJSON(json).equals(json);
        } catch (JSONException e) {
            return false;
        }
    }
}
