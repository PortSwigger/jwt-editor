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


import com.blackberry.jwteditor.model.jose.JWEFactory;
import com.blackberry.jwteditor.model.jose.JWSFactory;
import com.blackberry.jwteditor.model.jose.MutableJOSEObject;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;

class EditorModelTest {
    private static final String JWS = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    private static final String JWE = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBMV81In0.tZ6jXRdCReFX-3OBmQ36ZaW7AdNe3mNkEDTeQaFcQlDcnHeEJQhDYZkQWvWIO-VJduX38-Xc8odS30PoSarWeHMSUSxX6ugcRBazbmFDwzijwBgzFhviVedDiajeX-J5-jB8Qw-zyBXh7sjelhUfmYV6FWTJT-Ii1iVJQyR4sf8vhCiNF_Ri2yQtPjbYXnOxcuUvrSjOfbmlQb_wskZpPe8A60-PKbYqP0C11vgGLver0dXRgwh1sLcgjKX4WkT2casAL-2Hma1wXxSqTNtjrrzf4TKgnFleLQi_AbAVU2t34zhYgCBnXYj5gSLHClFtP-_Z1DHQA90IyZv9QxFUzA.IHVbU_e0fiP3Ioqf.5immwQ--k8GfBQXBuJgqt5EilHFKaTYxlcpU6wTvqtmx2_9-H9tsHDAduhCU8S8gNmS5_dZdmHjr6WgRjwFKpqBFX_W6LNnGVsZaGeFgoNdX2fv-hoDM-uSA2-nVa15k6IZ_flatCcW5eCxq9BST9Hhr2viCy1E9vgdZktTBrSxgDabpsGeZnCOTgi4lew6-KPVx-v5oKB0ZTOOdysT4G6fVySLQhjPzTWMFI-nlAIf0uVKImTbqTlnBbekD0SvEBFuFj_pMFhPNdrHf0kl6ve8E--qLJFroLiuQHpqsxGAEPVgyfbJovcEgh3vhkz0RL8Ym2r5ZeZdymEWGWVKIby4oANDgGHrIslwBNP1mtfRSOC2TP83qLEFMNxwmQjR-5HBedf6koS0yW_9jOvCWKjx4cR-ks3V5hmh1GlBsdRWB7scj-8OPUH7wqg-Hgxjfo9emqIhD3dxdSoDWkMzMUmcMtLXFQaNkWUZFK6m9o2GENRKSW8eGo2tZ3XuniMggFKvc1zGhcHlJPip__SHYfpdUnP7e45MkxybmIcvD7xVVahaWA_9PF77hGC0_6h2rtccYQJG-k8MgGpVlLQHJp55ZD3Nz2dRth85Cwhjz8tGOe_tY697OsbXxS1J2vqnUUc_K4SxSI6pLuZi7VMs.p2TlAQem1WnKeaKJiZyPGw";
    private static final String ALTERNATE_JWS = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZXN0In0.WVLalefVZ5Rj991Cjgh0qBjKSIQaqC_CgN3b-30GKpQ";
    private static final String ALTERNATE_JWE = "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJWcUtNak56OXpjcl9zaWJrNnhqcmJwUFZDUzk1UEdSU0dHYkVpMG5qWldBIiwieSI6IlFWMWpxSXBTZTVQSU80eVpTZTBKcnR1bkx4QTJ2ZHRnSnFfV18wNTNweDQifSwiZW5jIjoiQTEyOEdDTSIsImFsZyI6IkVDREgtRVMifQ..00TznoP0a4LjQTDR.vAwRkLB7GbK8ptyhfXqDwn_Hm8hbP4HBdmrvjvpxxRlxJxKcCoZngO9r_eb11vmi1oUhCVdFwzH_7-eSrzjv7ouoyVmv_ujMWweNvyKQdxJBmNlU8h3eR_TWjOLFetGhOhlnWtp95o4w4lNT4YyMGk66Ki6aG1UDLgK-WwLLcFbOLX7HPEk2ml8eQCnuqbjlCk7cWVtvoJ4xyLrLlEjJ3U_yXy8KPu0oAPI-Nxl3Nj1vG6KT_TqYaRHydr2wrT5A7cMOse6bwXPS_8uCp12EY8CQGkh7d9y63Fte7j8Bqmu_yJhKAoSkyoEOBTAvvzd-EhoLMBlWm3ouULg3MIt9gL-QZi8npXSrgiBCTw4Z2exew6WQIlV7JWGphcZYePFZHUvWf4Sd59fUvPaztuzhyHS3XaSwO_fOSPeYnX3a9wCH7Crcmldi-kiirKkh4QVSPUlCQyC0ihHot1PVwfUQDWXLAL4g0FJGZApkgAM9YBLkJpUQeT-qGjAhtoEGKQH6WTKOGaP65ZBORChDJThrFARYbJI1mqdc3gr5eBd1_FQsfxG5_Desg5AdpjIALyfYq8X39UmCLnx2tF4Yy6nIe79lIxqOOZA2XKYStrGmQORoOVQ8r91UbmC6tYJStPmVUWzXG47tUWLUBEktKtCl.9pZsA42F2w79Mi0AK84wVg";
    private static final String REQUEST_WITHOUT_JWT = "GET / HTTP/1.0\r\n\r\n";
    private static final String REQUEST_WITH_JWS = "GET / HTTP/1.0\r\nCookie: session=%s\r\n\r\n".formatted(JWS);
    private static final String REQUEST_WITH_ALTERNATE_JWS = "GET / HTTP/1.0\r\nCookie: session=%s\r\n\r\n".formatted(ALTERNATE_JWS);
    private static final String REQUEST_WITH_JWE = "POST / HTTP/1.0\r\nContent-Length: %d\r\n\r\n%s".formatted(JWE.length(), JWE);
    private static final String REQUEST_WITH_ALTERNATE_JWE = "POST / HTTP/1.0\r\nContent-Length: %d\r\n\r\n%s".formatted(JWE.length(), ALTERNATE_JWE);
    private static final String REQUEST_WITH_JWS_AND_JWE = "POST / HTTP/1.0\r\nCookie: session=%s\r\nContent-Length: %d\r\n\r\n%s".formatted(JWS, JWE.length(), JWE);
    private static final String REQUEST_WITH_ALTERNATE_JWS_AND_JWE = "POST / HTTP/1.0\r\nCookie: session=%s\r\nContent-Length: %d\r\n\r\n%s".formatted(ALTERNATE_JWS, JWE.length(), JWE);
    private static final String REQUEST_WITH_JWS_AND_ALTERNATE_JWE = "POST / HTTP/1.0\r\nCookie: session=%s\r\nContent-Length: %d\r\n\r\n%s".formatted(JWS, JWE.length(), ALTERNATE_JWE);
    private static final String REQUEST_WITH_ALTERNATE_JWS_AND_ALTERNATE_JWE = "POST / HTTP/1.0\r\nCookie: session=%s\r\nContent-Length: %d\r\n\r\n%s".formatted(ALTERNATE_JWS, JWE.length(), ALTERNATE_JWE);

    @Test
    void givenEmptyMessage_whenJOSEObjectStringsRetrieved_thenListIsEmpty() {
        EditorModel model = new EditorModel();

        model.setMessage("");

        assertThat(model.getJOSEObjectStrings()).isEmpty();
    }

    @Test
    void givenEmptyMessage_whenIsModifiedCalled_thenFalseReturned() {
        EditorModel model = new EditorModel();

        model.setMessage("");

        assertThat(model.isModified()).isFalse();
    }

    @Test
    void givenEmptyMessage_whenGetMessageCalled_thenMessageIsEmpty() {
        EditorModel model = new EditorModel();

        model.setMessage("");

        assertThat(model.getMessage()).isEmpty();
    }

    @Test
    void givenRequestWithoutJWT_whenJOSEObjectStringsRetrieved_thenListIsEmpty() {
        EditorModel model = new EditorModel();

        model.setMessage(REQUEST_WITHOUT_JWT);

        assertThat(model.getJOSEObjectStrings()).isEmpty();
    }

    @Test
    void givenRequestWithoutJWT_whenIsModifiedCalled_thenFalseReturned() {
        EditorModel model = new EditorModel();

        model.setMessage(REQUEST_WITHOUT_JWT);

        assertThat(model.isModified()).isFalse();
    }

    @Test
    void givenRequestWithoutJWT_whenGetMessageCalled_thenMessageIsInvariant() {
        EditorModel model = new EditorModel();

        model.setMessage(REQUEST_WITHOUT_JWT);

        assertThat(model.getMessage()).isEqualTo(REQUEST_WITHOUT_JWT);
    }

    @Test
    void givenRequestWithJWS_whenJOSEObjectStringsRetrieved_thenListIsHasSingleEntry() {
        EditorModel model = new EditorModel();

        model.setMessage(REQUEST_WITH_JWS);

        assertThat(model.getJOSEObjectStrings()).containsExactly("1 - " + JWS);
    }

    @Test
    void givenRequestWithUnmodifiedJWS_thenIsModifiedCalled_thenFalseReturned() {
        EditorModel model = new EditorModel();

        model.setMessage(REQUEST_WITH_JWS);

        assertThat(model.isModified()).isFalse();
    }

    @Test
    void giveRequestWithUnmodifiedJWS_whenGetMessageCalled_thenMessageIsInvariant() {
        EditorModel model = new EditorModel();

        model.setMessage(REQUEST_WITH_JWS);

        assertThat(model.getMessage()).isEqualTo(REQUEST_WITH_JWS);
    }

    @Test
    void givenRequestWithJWS_whenJOSEObjectRetrieved_thenCorrectObjectReturned() {
        EditorModel model = new EditorModel();
        model.setMessage(REQUEST_WITH_JWS);

        MutableJOSEObject joseObject = model.getJOSEObject(0);

        assertThat(joseObject.getOriginal()).isEqualTo(JWS);
    }

    @Test
    void givenRequestWithJWS_whenJOSEObjectModified_thenIsModifiedIsTrue() throws ParseException {
        EditorModel model = new EditorModel();
        model.setMessage(REQUEST_WITH_JWS);

        model.getJOSEObject(0).setModified(JWSFactory.parse(ALTERNATE_JWS));

        assertThat(model.isModified()).isTrue();
    }

    @Test
    void giveRequestWithModifiedJWS_whenGetMessageCalled_thenMessageIsUpdated() throws ParseException {
        EditorModel model = new EditorModel();
        model.setMessage(REQUEST_WITH_JWS);

        model.getJOSEObject(0).setModified(JWSFactory.parse(ALTERNATE_JWS));

        assertThat(model.getMessage()).isEqualTo(REQUEST_WITH_ALTERNATE_JWS);
    }

    @Test
    void givenRequestWithJWE_whenJOSEObjectStringsRetrieved_thenListIsHasSingleEntry() {
        EditorModel model = new EditorModel();

        model.setMessage(REQUEST_WITH_JWE);

        assertThat(model.getJOSEObjectStrings()).containsExactly("1 - " + JWE);
    }

    @Test
    void givenRequestWithUnmodifiedJWE_thenIsModifiedCalled_thenFalseReturned() {
        EditorModel model = new EditorModel();

        model.setMessage(REQUEST_WITH_JWE);

        assertThat(model.isModified()).isFalse();
    }

    @Test
    void giveRequestWithUnmodifiedJWE_whenGetMessageCalled_thenMessageIsInvariant() {
        EditorModel model = new EditorModel();

        model.setMessage(REQUEST_WITH_JWE);

        assertThat(model.getMessage()).isEqualTo(REQUEST_WITH_JWE);
    }

    @Test
    void givenRequestWithJWE_whenJOSEObjectRetrieved_thenCorrectObjectReturned() {
        EditorModel model = new EditorModel();
        model.setMessage(REQUEST_WITH_JWE);

        MutableJOSEObject joseObject = model.getJOSEObject(0);

        assertThat(joseObject.getOriginal()).isEqualTo(JWE);
    }

    @Test
    void givenRequestWithJWE_whenJOSEObjectModified_thenIsModifiedIsTrue() throws ParseException {
        EditorModel model = new EditorModel();
        model.setMessage(REQUEST_WITH_JWE);

        model.getJOSEObject(0).setModified(JWEFactory.parse(ALTERNATE_JWE));

        assertThat(model.isModified()).isTrue();
    }

    @Test
    void giveRequestWithModifiedJWE_whenGetMessageCalled_thenMessageIsUpdated() throws ParseException {
        EditorModel model = new EditorModel();
        model.setMessage(REQUEST_WITH_JWE);

        model.getJOSEObject(0).setModified(JWEFactory.parse(ALTERNATE_JWE));

        assertThat(model.getMessage()).isEqualTo(REQUEST_WITH_ALTERNATE_JWE);
    }

    @Test
    void givenRequestWithJWSAndJWE_whenJOSEObjectStringsRetrieved_thenListIsHasTwoEntries() {
        EditorModel model = new EditorModel();

        model.setMessage(REQUEST_WITH_JWS_AND_JWE);

        assertThat(model.getJOSEObjectStrings()).containsExactly("1 - " + JWS, "2 - " + JWE);
    }

    @Test
    void givenRequestWithUnmodifiedJWSAndJWE_thenIsModifiedCalled_thenFalseReturned() {
        EditorModel model = new EditorModel();

        model.setMessage(REQUEST_WITH_JWS_AND_JWE);

        assertThat(model.isModified()).isFalse();
    }

    @Test
    void giveRequestWithUnmodifiedJWSAndJWE_whenGetMessageCalled_thenMessageIsInvariant() {
        EditorModel model = new EditorModel();

        model.setMessage(REQUEST_WITH_JWS_AND_JWE);

        assertThat(model.getMessage()).isEqualTo(REQUEST_WITH_JWS_AND_JWE);
    }

    @Test
    void givenRequestWithJWSAndJWE_whenJOSEObjectRetrieved_thenCorrectObjectsReturned() {
        EditorModel model = new EditorModel();
        model.setMessage(REQUEST_WITH_JWS_AND_JWE);

        MutableJOSEObject jwsObject = model.getJOSEObject(0);
        MutableJOSEObject jweObject = model.getJOSEObject(1);

        assertThat(jwsObject.getOriginal()).isEqualTo(JWS);
        assertThat(jweObject.getOriginal()).isEqualTo(JWE);
    }

    @Test
    void givenRequestWithJWSAndJWE_whenJWSModified_thenIsModifiedIsTrue() throws ParseException {
        EditorModel model = new EditorModel();
        model.setMessage(REQUEST_WITH_JWS_AND_JWE);

        model.getJOSEObject(0).setModified(JWSFactory.parse(ALTERNATE_JWS));

        assertThat(model.isModified()).isTrue();
    }

    @Test
    void givenRequestWithJWSAndJWE_whenJWEModified_thenIsModifiedIsTrue() throws ParseException {
        EditorModel model = new EditorModel();
        model.setMessage(REQUEST_WITH_JWS_AND_JWE);

        model.getJOSEObject(1).setModified(JWEFactory.parse(ALTERNATE_JWE));

        assertThat(model.isModified()).isTrue();
    }

    @Test
    void giveRequestWithJWSAndJWE_whenJWSModifiedAndGetMessageCalled_thenMessageIsUpdated() throws ParseException {
        EditorModel model = new EditorModel();
        model.setMessage(REQUEST_WITH_JWS_AND_JWE);

        model.getJOSEObject(0).setModified(JWSFactory.parse(ALTERNATE_JWS));

        assertThat(model.getMessage()).isEqualTo(REQUEST_WITH_ALTERNATE_JWS_AND_JWE);
    }

    @Test
    void giveRequestWithJWSAndJWE_whenJWEModifiedAndGetMessageCalled_thenMessageIsUpdated() throws ParseException {
        EditorModel model = new EditorModel();
        model.setMessage(REQUEST_WITH_JWS_AND_JWE);

        model.getJOSEObject(1).setModified(JWEFactory.parse(ALTERNATE_JWE));

        assertThat(model.getMessage()).isEqualTo(REQUEST_WITH_JWS_AND_ALTERNATE_JWE);
    }

    @Test
    void giveRequestWithModifiedJWSAndJWE_whenGetMessageCalled_thenMessageIsUpdated() throws ParseException {
        EditorModel model = new EditorModel();
        model.setMessage(REQUEST_WITH_JWS_AND_JWE);

        model.getJOSEObject(0).setModified(JWSFactory.parse(ALTERNATE_JWS));
        model.getJOSEObject(1).setModified(JWEFactory.parse(ALTERNATE_JWE));

        assertThat(model.getMessage()).isEqualTo(REQUEST_WITH_ALTERNATE_JWS_AND_ALTERNATE_JWE);
    }
}