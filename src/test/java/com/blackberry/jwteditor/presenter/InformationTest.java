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

package com.blackberry.jwteditor.presenter;

import com.blackberry.jwteditor.model.jose.Information;
import com.blackberry.jwteditor.model.jose.TimeClaim;
import com.blackberry.jwteditor.model.jose.TimeClaimFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static com.blackberry.jwteditor.model.jose.TimeClaimType.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class InformationTest {

    static Stream<Arguments> data() {
        return Stream.of(
                arguments(new TimeClaim(ISSUED_AT_TIME, "isogeny", null), "Issued At - invalid value: isogeny", true),
                arguments(TimeClaimFactory.fromEpochSeconds(ISSUED_AT_TIME, "1516239022"), "Issued At - Thu Jan 18 2018 01:30:22", false),
                arguments(TimeClaimFactory.fromEpochSeconds(ISSUED_AT_TIME, "2516239022"), "Issued At - Sun Sep 26 2049 03:17:02", true),
                arguments(new TimeClaim(NOT_BEFORE_TIME, "isogeny", null), "Not Before - invalid value: isogeny", true),
                arguments(TimeClaimFactory.fromEpochSeconds(NOT_BEFORE_TIME, "1516239022"), "Not Before - Thu Jan 18 2018 01:30:22", false),
                arguments(TimeClaimFactory.fromEpochSeconds(NOT_BEFORE_TIME, "2516239022"), "Not Before - Sun Sep 26 2049 03:17:02", true),
                arguments(new TimeClaim(EXPIRATION_TIME, "isogeny", null), "Expiration Time - invalid value: isogeny", true),
                arguments(TimeClaimFactory.fromEpochSeconds(EXPIRATION_TIME, "1516239022"), "Expiration Time - Thu Jan 18 2018 01:30:22", true),
                arguments(TimeClaimFactory.fromEpochSeconds(EXPIRATION_TIME, "2516239022"), "Expiration Time - Sun Sep 26 2049 03:17:02", false));
    }

    @MethodSource("data")
    @ParameterizedTest
    void testInformationFromTimeClaims(TimeClaim timeClaim, String expectedText, boolean expectedIsWarning) {
        Information information = Information.from(timeClaim);

        assertThat(information.text()).isEqualTo(expectedText);
        assertThat(information.isWarning()).isEqualTo(expectedIsWarning);
    }
}