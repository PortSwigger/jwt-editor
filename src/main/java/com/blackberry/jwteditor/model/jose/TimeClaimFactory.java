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

import org.json.JSONException;
import org.json.JSONObject;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Optional;

import static java.time.ZoneOffset.UTC;
import static java.time.format.DateTimeFormatter.ISO_DATE_TIME;
import static java.util.Arrays.stream;
import static java.util.Collections.emptyList;

public class TimeClaimFactory {

    public static TimeClaim fromEpochSeconds(TimeClaimType type, String value) {
        return new TimeClaim(type, value, dateTimeValue(value));
    }

    public static TimeClaim fromIsoDateTime(TimeClaimType type, String value) {
        return new TimeClaim(type, value, parseDateTime(value));
    }

    static List<TimeClaim> fromPayloadJson(String payloadJson) {
        Optional<JSONObject> optional = parsePayload(payloadJson);

        if (optional.isEmpty()) {
            return emptyList();
        }

        JSONObject jsonObject = optional.get();

        return stream(TimeClaimType.values())
                .filter(type -> jsonObject.has(type.name))
                .map(type -> {
                            String value = jsonObject.get(type.name).toString();

                            if (value.matches("\\d+(.\\d+)?")) {
                                return fromEpochSeconds(type, value);
                            } else {
                                return fromIsoDateTime(type, value);
                            }
                        }
                )
                .toList();
    }

    private static Optional<JSONObject> parsePayload(String payloadJson) {
        try {
            return Optional.of(new JSONObject(payloadJson));
        } catch (JSONException e) {
            return Optional.empty();
        }
    }

    private static ZonedDateTime dateTimeValue(String numberValue) {
        if (numberValue == null) {
            return null;
        }

        try {
            // Try to parse string time value as BigDecimal to keep the floating point precision
            BigDecimal epochSecondsDecimal = new BigDecimal(numberValue);

            // Truncate decimal part of the value to get the seconds
            long seconds = epochSecondsDecimal.longValue();
            if (seconds < 0) {
                return null;
            }

            // Get decimal part as nanoseconds
            long nanoseconds = epochSecondsDecimal.subtract(new BigDecimal(seconds))
                    .movePointRight(9)
                    .longValue();

            Instant instant = Instant.ofEpochSecond(seconds, nanoseconds);
            return ZonedDateTime.ofInstant(instant, UTC);
        } catch (NumberFormatException | ArithmeticException e) {
            return null;
        }
    }

    private static ZonedDateTime parseDateTime(String value) {
        try {
            return ZonedDateTime.parse(value, ISO_DATE_TIME);
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}
