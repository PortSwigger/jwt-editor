/*
Author : Dolph Flynn

Copyright 2025 Dolph Flynn

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

package com.blackberry.jwteditor.model.keys;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.text.ParseException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JWKSetParserTest {
    private final JWKSetParser parser = new JWKSetParser();

    @ValueSource(strings = {
            "'",
            "{",
            "["
    })
    @ParameterizedTest
    void givenInvalidJson_whenParsed_thenParseExceptionThrown(String json) {
        assertThrows(ParseException.class, () -> parser.parse(json));
    }

    @ValueSource(strings = {
            "null",
            "3",
            "'jwt'",
            "\"jwt\"",
            "[]"
    })
    @ParameterizedTest
    void givenNonObjectJson_whenParsed_thenParseExceptionThrown(String json) {
        assertThrows(ParseException.class, () -> parser.parse(json));
    }

    @ValueSource(strings = {
            "{}",
            "{ 'jwt':[] }",
    })
    @ParameterizedTest
    void givenJsonObjectWithoutKeys_whenParsed_thenParseExceptionThrown(String json) {
        assertThrows(ParseException.class, () -> parser.parse(json));
    }

    @Test
    void givenJsonObjectWithEmptyKeysList_whenParsed_thenEmptyListReturned() throws ParseException {
        String json = """
                { "keys" : [] }
                """;

        assertThat(parser.parse(json)).isEmpty();
    }

    @Test
    void givenJsonObjectWithAsymmetricKeys_whenParsed_thenKeysReturned() throws ParseException {
        String json = """
                {"keys":
                       [
                         {"kty":"EC",
                          "crv":"P-256",
                          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                          "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
                          "use":"enc",
                          "kid":"1"},
                
                         {"kty":"RSA",
                          "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4jcbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                          "e":"AQAB",
                          "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
                          "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
                          "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
                          "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
                          "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
                          "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
                          "alg":"RS256",
                          "kid":"2011-04-29"}
                       ]
                     }
                """;

        List<Key> keys = parser.parse(json);

        assertThat(keys).hasSize(2);

        Key firstKey = keys.getFirst();
        assertThat(firstKey).isInstanceOf(ECJWKKey.class);
        ECJWKKey ecKey = (ECJWKKey) firstKey;
        assertThat(ecKey.getID()).isEqualTo("1");

        Key secondKey = keys.getLast();
        assertThat(secondKey).isInstanceOf(RSAJWKKey.class);
        RSAJWKKey rsaKey = (RSAJWKKey) secondKey;
        assertThat(rsaKey.getID()).isEqualTo("2011-04-29");
    }

    @Test
    void givenJsonObjectWithSymmetricKey_whenParsed_thenKeyReturned() throws ParseException {
        String json = """
                {"keys":
                       [
                         {"kty":"oct",
                          "alg":"A128KW",
                          "k":"GawgguFyGrWKav7AX4VKUg"},
                
                         {"kty":"oct",
                          "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
                          "kid":"HMAC key used in JWS spec Appendix A.1 example"}
                       ]
                     }
                """;

        List<Key> keys = parser.parse(json);

        assertThat(keys).hasSize(2);

        Key firstKey = keys.getFirst();
        assertThat(firstKey).isInstanceOf(OctetSequenceKeyJWKKey.class);
        OctetSequenceKeyJWKKey firstOctetSequenceKey = (OctetSequenceKeyJWKKey) firstKey;
        assertThat(firstOctetSequenceKey.getID()).isNull();

        Key secondKey = keys.getLast();
        assertThat(secondKey).isInstanceOf(OctetSequenceKeyJWKKey.class);
        OctetSequenceKeyJWKKey secondOctetSequenceKey = (OctetSequenceKeyJWKKey) secondKey;
        assertThat(secondOctetSequenceKey.getID()).isEqualTo("HMAC key used in JWS spec Appendix A.1 example");
    }
}