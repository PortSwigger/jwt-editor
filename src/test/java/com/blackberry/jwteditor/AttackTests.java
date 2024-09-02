/*
Author : Fraser Winterborn

Copyright 2021 BlackBerry Limited

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

package com.blackberry.jwteditor;

import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.jose.JWSFactory;
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.JWKKeyFactory;
import com.blackberry.jwteditor.operations.Attacks;
import com.blackberry.jwteditor.utils.PEMUtils;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import utils.BouncyCastleExtension;

import java.text.ParseException;
import java.util.Map;

import static com.nimbusds.jose.HeaderParameterNames.ALGORITHM;
import static com.nimbusds.jose.HeaderParameterNames.KEY_ID;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(BouncyCastleExtension.class)
class AttackTests {
    // Using values from https://www.nccgroup.com/ae/about-us/newsroom-and-events/blogs/2019/january/jwt-attack-walk-through/ to verify
    private static final String HMAC_KEY_CONFUSION_JWS = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU0NzcyOTY2MiwiZXhwIjoxNTQ3Nzk5OTk5LCJkYXRhIjp7Ik5DQyI6InRlc3QifX0.";
    private static final String HMAC_KEY_CONFUSION_EXPECTED_JWS = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU0NzcyOTY2MiwiZXhwIjoxNTQ3Nzk5OTk5LCJkYXRhIjp7Ik5DQyI6InRlc3QifX0.2zobdg7sgeApcEaR9ngMTRZT1dkWiMJOWYkelzQu5Z8";
    private static final String HMAC_KEY_CONFUSION_PEM = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqi8TnuQBGXOGx/Lfn4JF
            NYOH2V1qemfs83stWc1ZBQFCQAZmUr/sgbPypYzy229pFl6bGeqpiRHrSufHug7c
            1LCyalyUEP+OzeqbEhSSuUss/XyfzybIusbqIDEQJ+Yex3CdgwC/hAF3xptV/2t+
            H6y0Gdh1weVKRM8+QaeWUxMGOgzJYAlUcRAP5dRkEOUtSKHBFOFhEwNBXrfLd76f
            ZXPNgyN0TzNLQjPQOy/tJ/VFq8CQGE4/K5ElRSDlj4kswxonWXYAUVxnqRN1LGHw
            2G5QRE2D13sKHCC8ZrZXJzj67Hrq5h2SADKzVzhA8AW3WZlPLrlFT3t1+iZ6m+aF
            KwIDAQAB
            -----END PUBLIC KEY-----""";

    private static final String EMBEDDED_JWK_KEY = "{\"p\":\"6g4o__Z8GnI2UtRz6AJdD0dVRmZqq1bONXWq6ee70eVHmu-fZ2XQCYj6miF1DT-QHDA1eb7QxKnb5b-HZ2L-OXf6OLtu6xNBmQjT1ZcGHe8YHmNfJN4CP-nxG4EYJRoInZOvQwBEWfXIrqvw0HhGXTrfC8GGHtb1uCP733cITaU\",\"kty\":\"RSA\",\"q\":\"tvQO0f6XevKrWzHDfjfQ_dQohOIpRYMIuiEohAMqphgeVh3VUJHAnigWkHllvJN6wsJcZM9TfXiKFjdEtgl_L9igTJ8BTAJD2yLl_qfnjpODLR7A--AnyFEEFtgO-FfnFRQlBC50-Bfz4JxF5K7hXAYs1X5GHp0j6SyjO7wSaFU\",\"d\":\"SWgkfMybZJ6zFZgVpgLMgjTHWfvrC4MRvtjmif2haSiYHQRB0IgY5_kSUKvp00reb4Xa_Asx1gjq6lrfd8iIt_OSJNkS7Od3s_K6pP_o7WAtl3UUuMqSdZSmJXiPzlkCBldnjsHRU1kqolfiT07m9zCS972ZTilYoErVk9eOCcazPvEihUcyDGTcx2H7cXrZaqrlliQNUpTCWw6SHspq2V4FLGZrioFDCOkbAL1rgD5mg2mANMLv1UY7JWVueuvzs8jnvsGnhRQlnhf7QgSFXUUfhoy-Ej2rWrfYZ5_i17tuGkjqiq0vzAA1U28REZEBHjDQ4p_8vCtHgz3Lc-75UQ\",\"e\":\"AQAB\",\"kid\":\"dfc6a9df-916c-406d-84de-ce5b49d50ad0\",\"qi\":\"Pl4ANTrzCLGsE5IE3jkJiqeOq6Z3HXrQsv39NXQNriLAyghQPgrcnN4rGLaBRi1DKFElU4qmCLXzwaylox-vJd_W4WD-2UFvaSD4h_EUjGSfpcfEPTONECF5WTRHwDCNRVu7XaK53jp0nadsiFaa8a1SmP58uZwl869Bp0Hskks\",\"dp\":\"lLJSUeuihJqy8ISQ7oEx5hcHkiZW9mu7rjMHVnsm0_66MzCxMNt6A9TGgU1oM_aB86adEq-rqoXPcnLv7zrxEEms6oYJvccKEdON4VCFTlcsF4JCXAW_oCNcToEBefDEMHg3DHYK9qwzxuTtpUQEUA6qzakxMD6Y9VfHGP1ihRE\",\"dq\":\"nnRItbXUCsdMhEJYd-Pt3Tm4EkcyyaKQl2yKg7OeZ5ZyB9H048Ao3JIJ4P1TkP0GkNH3ZdRvEjepGU6q8yLMhmsPgu0gGW3IyW2zV1ii48h9D0IYkM32hrcsXICqjorLeGUnHjUCV7GfJoUSv9p7EtHCWPHx1yfwZ06i3eSo6LU\",\"n\":\"p0U0MdHFLPovX5j91oH-dc54oeJDIDapuPDM9gYHjhX2Bwj4fFhqvaAfIhn-w7zm-6HZsH-VxPCngl7GkWxx1F7Cobkg8TOD4UusFFo8srSFDExWCQ4MRFDRcLN9bmfXeiR-MvGE1tHZNJCOnxsx32-ueF0T2xo880-073skum8sS9vi7RuNhaCY_liJNkrznqQCEbNLR_-V_-IQaFG_obDNqEHroKC3lxz34s4CPpUwen8IFJm8_vbcFiI_jZrw_VTwJM4Il5Hr2uJLv_ahsZTLomumJmabvXulgQFBK4hEd-FH4c72glbFfFLEkzRQz-ozCzySudbRG9UvhubPyQ\"}";
    private static final String EMBEDDED_JWK_EXPECTED_JWS = "eyJraWQiOiJkZmM2YTlkZi05MTZjLTQwNmQtODRkZS1jZTViNDlkNTBhZDAiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsImtpZCI6ImRmYzZhOWRmLTkxNmMtNDA2ZC04NGRlLWNlNWI0OWQ1MGFkMCIsIm4iOiJwMFUwTWRIRkxQb3ZYNWo5MW9ILWRjNTRvZUpESURhcHVQRE05Z1lIamhYMkJ3ajRmRmhxdmFBZklobi13N3ptLTZIWnNILVZ4UENuZ2w3R2tXeHgxRjdDb2JrZzhUT0Q0VXVzRkZvOHNyU0ZERXhXQ1E0TVJGRFJjTE45Ym1mWGVpUi1NdkdFMXRIWk5KQ09ueHN4MzItdWVGMFQyeG84ODAtMDczc2t1bThzUzl2aTdSdU5oYUNZX2xpSk5rcnpucVFDRWJOTFJfLVZfLUlRYUZHX29iRE5xRUhyb0tDM2x4ejM0czRDUHBVd2VuOElGSm04X3ZiY0ZpSV9qWnJ3X1ZUd0pNNElsNUhyMnVKTHZfYWhzWlRMb211bUptYWJ2WHVsZ1FGQks0aEVkLUZINGM3MmdsYkZmRkxFa3pSUXotb3pDenlTdWRiUkc5VXZodWJQeVEifX0.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU0NzcyOTY2MiwiZXhwIjoxNTQ3Nzk5OTk5LCJkYXRhIjp7Ik5DQyI6InRlc3QifX0.Fte7ISfZ15DGtYwql8Ej1rou0Kf5Lut3qpxUS2zcp5UsRapQTyU5nehvVZD5BKq_xKRkG0SEVlRbF6Z2FAsG7Al3NXKc257xKc1djt_toh7nsDZPWycfj91FrLVJW5dN06PNgDjkCVlcdM2x_awesc3bApLg7bmcEkxsMoPqUjDBLxo6h-AHEo_7F-0R7mOAC5cSUCsCosEnnwMG7ihC_bPkD9cGUwq5UEPjzVCToavIXXWjNRpHXSob9aGuKUlYao92VoYIuOH51YcyAspzXD3lDViG8ZxOPVTf3T7ZDUmfy161XDRyvmRxeUVSRSUzAt3-WdMjmP8YRylYCC36Ew";

    @ParameterizedTest
    @ValueSource(strings = {"none", "None", "NONE", "nOnE"})
    void testSigningKeyNone(String algorithm) throws ParseException {
        JWS jws = JWSFactory.parse(HMAC_KEY_CONFUSION_JWS);
        JWS modifiedJWS = Attacks.noneSigning(jws, algorithm);

        assertThat(modifiedJWS.getHeader()).isEqualTo(String.format("{\"typ\":\"JWT\",\"alg\":\"%s\"}", algorithm));
        assertThat(modifiedJWS.getEncodedPayload().toString()).isEqualTo(HMAC_KEY_CONFUSION_JWS.split("\\.")[1]);
        assertThat(modifiedJWS.getSignature()).isEmpty();
    }

    @Test
    void testHMACKeyConfusion() throws Exception {
        JWS jws = JWSFactory.parse(HMAC_KEY_CONFUSION_JWS);
        JWS expectedJWS = JWSFactory.parse(HMAC_KEY_CONFUSION_EXPECTED_JWS);
        JWKKey key = JWKKeyFactory.from(PEMUtils.pemToRSAKey(HMAC_KEY_CONFUSION_PEM));

        JWS modifiedJWS  = Attacks.hmacKeyConfusion(jws, key, JWSAlgorithm.HS256, false);

        assertThat(modifiedJWS.getSignature()).isEqualTo(expectedJWS.getSignature());
    }

    @Test
    // Test the Embedded JWK attack produces a known-good value
    void testEmbeddedJWKKnown() throws Exception {
        JWS jws = JWSFactory.parse(HMAC_KEY_CONFUSION_JWS);
        JWKKey jwk = JWKKeyFactory.from(JWK.parse(EMBEDDED_JWK_KEY));

        JWS modifiedJWS = Attacks.embeddedJWK(jws, jwk, JWSAlgorithm.RS256);

        assertThat(modifiedJWS.serialize()).isEqualTo(EMBEDDED_JWK_EXPECTED_JWS);
    }

    // Test the Embedded JWK attack with all signing key types
    @ParameterizedTest
    @MethodSource("com.blackberry.jwteditor.KeyUtils#keySigningAlgorithmPairs")
    void testEmbeddedJWKAll(JWKKey jwk, JWSAlgorithm alg) throws Exception {
        JWS jws = JWSFactory.parse(HMAC_KEY_CONFUSION_JWS);

        JWS signedJWS = Attacks.embeddedJWK(jws, jwk, alg);
        Map<String, Object> headerJsonMap = JSONObjectUtils.parse(signedJWS.getHeader());

        assertThat(headerJsonMap.get(ALGORITHM)).isEqualTo(alg.getName());
        assertThat(headerJsonMap.get(KEY_ID)).isEqualTo(jwk.getID());
        assertThat(signedJWS.getEncodedPayload()).isEqualTo(jws.getEncodedPayload());

        JWSHeader signingInfo = new JWSHeader.Builder(alg).build();
        assertThat(signedJWS.verify(jwk, signingInfo)).isTrue();
    }
}
