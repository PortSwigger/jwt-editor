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

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import static java.util.Locale.US;

public record TimeClaim(TimeClaimType type, String value, ZonedDateTime dateTime) {
    private static final String DATE_TIME_PATTERN = "EEE MMM dd yyyy HH:mm:ss";
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern(DATE_TIME_PATTERN).withLocale(US);

    public String date() {
        return dateTime == null ? "" : FORMATTER.format(dateTime);
    }

    public boolean hasDate() {
        return dateTime != null;
    }

    public boolean isValid() {
        return type.isValid(dateTime);
    }
}
