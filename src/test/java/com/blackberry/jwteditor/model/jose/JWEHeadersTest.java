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

import com.nimbusds.jose.util.Base64URL;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;

class JWEHeadersTest {

    @Test
    void givenJWEWithCompactHeader_thenHeaderIsCompact() throws ParseException {
        JWE jwe = JWEFactory.parse("eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0..FJze_l4riv2Xp-wl.HtXmzfHH5FoStStIaUGAg5x03tZSkkfcuQVEhNZz5awdQ6UKduXie4iN10qG6hPAG9snH8peYwhHynkrVmW1grzWCTgSzwyWKUqfOL3J8iybvqDvTqAD4_UN3M59rcgVANNc3qQ3YupeSYC7H1H6RzMD-EHvJ51t5biUc1B0YCvFfi7HP5h6ArIUsLXGppO6kF79qqrWvpCO0LHAhZX8lR4syYP06_Y93JMvJ64_CtVlyYb79_fjF1L8_7j4ko_bTzkva5_ANjE2esshekNAo_ArQkCHexs_MPFrK6U4M21YN2nHkoT-Fsj0OyiZ3GBM89fRzZolsm-KqhuXxH9xV028KSxiCbT43LFRCD9SFjmQrGLqRNV7xtZkSeyvq-RwmvIkywPK7e2xIfpJpp6d6RUpJZC85ky4-FoK-SYpm8C5pBKwR37_2XV0fs7AFt6ixU-301wtHDSAcdFg6acbzlLsa-iyJnF6yoldnit5s5Jq9J6hRsZd9IfflitGBSB0Z6DhBQEDaMMG0--_wiMN68A9YoPq9dVdLibEoSY1ye7mFp_3oUVLRKvH5Fi_hGwTOZ3MANOnlvM1_158pvtApChLZBg2bMV65EmAQ53IIcVZMxqDDYX1KGqFf39Ds6EeyN1I_IQrCSgpxFiHZRtd.QWdXTJHhURgkfQC61FJjVQ");

        assertThat(jwe.header().isCompact()).isTrue();
    }

    @Test
    void givenJWEWithNonCompactHeader_thenHeaderIsNotCompact() throws ParseException {
        JWE jwe = JWEFactory.parse("ewogICAgImVuYyI6ICJBMTI4R0NNIiwKICAgICJhbGciOiAiUlNBMV81Igp9.BpN7moNZHMfK44D6U-A27cs4ELJAjVhmUw2anOiFz3prUHU5vOKe-dcuG-1mOK9hUb2mA-D1dHgdGYppX4pb-7lOyzKugN1s5e-ZrVIcK1mmzV8W9yFiHY6nURUiBaaNC83UYwWPXwSmagR68eKXP3uLBOc9zxF6P0MQukitUupqFTxm7hSIq364zB2ME9aj9Zvc7MISXey1wCqRvx8Jr2CuJdNTJKFk1I-v84WjdCU-isyUMJgFMFGdYkki31JA5E1AhmWat6Aq4Skyf3LFeXWKwwvsc40phy6sJWdG4LzqiaVmbw_V0VC0y1HoJubFE9VqE_Hdk1Izq6IciAA5yQ.2KAaxB0ky7qij3cZ.Hd6PtgFXGbpYBYzSttNr09lvxeapG3a3frwfa59jBBPIW74qRSBrn8zQ9U_gbCf8EkfWgeVdg3f46gbhnd5JrQk_vMXbBptXzj1l5MBNg524w8xOUXg6yCGQwWPbFVjz--N0SyEwQ_h2aS5da79RCr-igATSDWMXhyYq4pW1fbW68Mn-p9nqjb0UCHk6wwI-OtG1cUq3wEtLF7L3iJxlahCuJF_j7YFbxjpH5J3GkteKPD99LcuRbe1l7uKCsuL7_bM1FIoFEnbzfGPCoGBEY-r1TOGoYCO_4gPI6OgqIYSqNIAq0-8WX-8yhAiLY0Pm4kADHS8EDWkpbreD0gHoEZaDAGmdLrNuDgX-dXJXizujQmZt0NOidx4Y-b2Tq1_g6oPVhOWmFZ7lsq7FQ5DZ29rbgg8bCYB-HNNBSLQ24wkQy7v-EwgXxYRY25oTExqRMFDAAvyZjRlZZdtQIYtEs-6IS87oWufxCGw2nkeID8A0N4e1I1FHx9YYmD5_TANOt9yTBslGu6h9Vr1pFAXq7wbM2AV80SosnW08RkPDLxY87MiId18ls-Ri_5994XsfhaJ0P_geSCnF8T_ircq2Aw9Cs3G2mYBbnagey6x7ntCkQZgFUhYkScPbc92natU1OI7pdBqd-UdGnyk8eKfw.aXsSlREsWbR6M0-TE_3MRw");

        assertThat(jwe.header().isCompact()).isFalse();
    }

    @Test
    void givenJWEWithCompactHeader_thenPrettyPrintDecodedHeaderIsCorrect() throws ParseException {
        JWE jwe = JWEFactory.parse("eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0..FJze_l4riv2Xp-wl.HtXmzfHH5FoStStIaUGAg5x03tZSkkfcuQVEhNZz5awdQ6UKduXie4iN10qG6hPAG9snH8peYwhHynkrVmW1grzWCTgSzwyWKUqfOL3J8iybvqDvTqAD4_UN3M59rcgVANNc3qQ3YupeSYC7H1H6RzMD-EHvJ51t5biUc1B0YCvFfi7HP5h6ArIUsLXGppO6kF79qqrWvpCO0LHAhZX8lR4syYP06_Y93JMvJ64_CtVlyYb79_fjF1L8_7j4ko_bTzkva5_ANjE2esshekNAo_ArQkCHexs_MPFrK6U4M21YN2nHkoT-Fsj0OyiZ3GBM89fRzZolsm-KqhuXxH9xV028KSxiCbT43LFRCD9SFjmQrGLqRNV7xtZkSeyvq-RwmvIkywPK7e2xIfpJpp6d6RUpJZC85ky4-FoK-SYpm8C5pBKwR37_2XV0fs7AFt6ixU-301wtHDSAcdFg6acbzlLsa-iyJnF6yoldnit5s5Jq9J6hRsZd9IfflitGBSB0Z6DhBQEDaMMG0--_wiMN68A9YoPq9dVdLibEoSY1ye7mFp_3oUVLRKvH5Fi_hGwTOZ3MANOnlvM1_158pvtApChLZBg2bMV65EmAQ53IIcVZMxqDDYX1KGqFf39Ds6EeyN1I_IQrCSgpxFiHZRtd.QWdXTJHhURgkfQC61FJjVQ");

        String decodedHeader = jwe.header().decodeAndPrettyPrint();

        assertThat(decodedHeader).isEqualTo("""
                {
                    "enc": "A128GCM",
                    "alg": "dir"
                }""");
    }

    @Test
    void givenJWE_thenDecodedHeaderIsCorrect() throws ParseException {
        JWE jwe = JWEFactory.parse("eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0..FJze_l4riv2Xp-wl.HtXmzfHH5FoStStIaUGAg5x03tZSkkfcuQVEhNZz5awdQ6UKduXie4iN10qG6hPAG9snH8peYwhHynkrVmW1grzWCTgSzwyWKUqfOL3J8iybvqDvTqAD4_UN3M59rcgVANNc3qQ3YupeSYC7H1H6RzMD-EHvJ51t5biUc1B0YCvFfi7HP5h6ArIUsLXGppO6kF79qqrWvpCO0LHAhZX8lR4syYP06_Y93JMvJ64_CtVlyYb79_fjF1L8_7j4ko_bTzkva5_ANjE2esshekNAo_ArQkCHexs_MPFrK6U4M21YN2nHkoT-Fsj0OyiZ3GBM89fRzZolsm-KqhuXxH9xV028KSxiCbT43LFRCD9SFjmQrGLqRNV7xtZkSeyvq-RwmvIkywPK7e2xIfpJpp6d6RUpJZC85ky4-FoK-SYpm8C5pBKwR37_2XV0fs7AFt6ixU-301wtHDSAcdFg6acbzlLsa-iyJnF6yoldnit5s5Jq9J6hRsZd9IfflitGBSB0Z6DhBQEDaMMG0--_wiMN68A9YoPq9dVdLibEoSY1ye7mFp_3oUVLRKvH5Fi_hGwTOZ3MANOnlvM1_158pvtApChLZBg2bMV65EmAQ53IIcVZMxqDDYX1KGqFf39Ds6EeyN1I_IQrCSgpxFiHZRtd.QWdXTJHhURgkfQC61FJjVQ");

        String decodedHeader = jwe.header().decoded();

        assertThat(decodedHeader).isEqualTo("{\"enc\":\"A128GCM\",\"alg\":\"dir\"}");
    }

    @Test
    void givenJWE_thenEncodedHeaderIsCorrect() throws ParseException {
        JWE jwe = JWEFactory.parse("eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBMV81In0..FJze_l4riv2Xp-wl.HtXmzfHH5FoStStIaUGAg5x03tZSkkfcuQVEhNZz5awdQ6UKduXie4iN10qG6hPAG9snH8peYwhHynkrVmW1grzWCTgSzwyWKUqfOL3J8iybvqDvTqAD4_UN3M59rcgVANNc3qQ3YupeSYC7H1H6RzMD-EHvJ51t5biUc1B0YCvFfi7HP5h6ArIUsLXGppO6kF79qqrWvpCO0LHAhZX8lR4syYP06_Y93JMvJ64_CtVlyYb79_fjF1L8_7j4ko_bTzkva5_ANjE2esshekNAo_ArQkCHexs_MPFrK6U4M21YN2nHkoT-Fsj0OyiZ3GBM89fRzZolsm-KqhuXxH9xV028KSxiCbT43LFRCD9SFjmQrGLqRNV7xtZkSeyvq-RwmvIkywPK7e2xIfpJpp6d6RUpJZC85ky4-FoK-SYpm8C5pBKwR37_2XV0fs7AFt6ixU-301wtHDSAcdFg6acbzlLsa-iyJnF6yoldnit5s5Jq9J6hRsZd9IfflitGBSB0Z6DhBQEDaMMG0--_wiMN68A9YoPq9dVdLibEoSY1ye7mFp_3oUVLRKvH5Fi_hGwTOZ3MANOnlvM1_158pvtApChLZBg2bMV65EmAQ53IIcVZMxqDDYX1KGqFf39Ds6EeyN1I_IQrCSgpxFiHZRtd.QWdXTJHhURgkfQC61FJjVQ");

        Base64URL encodedHeader = jwe.header().encoded();

        assertThat(encodedHeader).isEqualTo(new Base64URL("eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBMV81In0"));
    }

    @Test
    void givenJWE_thenHeaderJsonIsCorrect() throws ParseException {
        JWE jwe = JWEFactory.parse("eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0..FJze_l4riv2Xp-wl.HtXmzfHH5FoStStIaUGAg5x03tZSkkfcuQVEhNZz5awdQ6UKduXie4iN10qG6hPAG9snH8peYwhHynkrVmW1grzWCTgSzwyWKUqfOL3J8iybvqDvTqAD4_UN3M59rcgVANNc3qQ3YupeSYC7H1H6RzMD-EHvJ51t5biUc1B0YCvFfi7HP5h6ArIUsLXGppO6kF79qqrWvpCO0LHAhZX8lR4syYP06_Y93JMvJ64_CtVlyYb79_fjF1L8_7j4ko_bTzkva5_ANjE2esshekNAo_ArQkCHexs_MPFrK6U4M21YN2nHkoT-Fsj0OyiZ3GBM89fRzZolsm-KqhuXxH9xV028KSxiCbT43LFRCD9SFjmQrGLqRNV7xtZkSeyvq-RwmvIkywPK7e2xIfpJpp6d6RUpJZC85ky4-FoK-SYpm8C5pBKwR37_2XV0fs7AFt6ixU-301wtHDSAcdFg6acbzlLsa-iyJnF6yoldnit5s5Jq9J6hRsZd9IfflitGBSB0Z6DhBQEDaMMG0--_wiMN68A9YoPq9dVdLibEoSY1ye7mFp_3oUVLRKvH5Fi_hGwTOZ3MANOnlvM1_158pvtApChLZBg2bMV65EmAQ53IIcVZMxqDDYX1KGqFf39Ds6EeyN1I_IQrCSgpxFiHZRtd.QWdXTJHhURgkfQC61FJjVQ");

        JSONObject headerJson = jwe.header().json();

        assertThat(headerJson.similar(new JSONObject("{\"enc\":\"A128GCM\",\"alg\":\"dir\"}"))).isTrue();
    }

    @Test
    void givenJWE_thenHeaderSerializationCorrect() throws ParseException {
        JWE jwe = JWEFactory.parse("eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0..FJze_l4riv2Xp-wl.HtXmzfHH5FoStStIaUGAg5x03tZSkkfcuQVEhNZz5awdQ6UKduXie4iN10qG6hPAG9snH8peYwhHynkrVmW1grzWCTgSzwyWKUqfOL3J8iybvqDvTqAD4_UN3M59rcgVANNc3qQ3YupeSYC7H1H6RzMD-EHvJ51t5biUc1B0YCvFfi7HP5h6ArIUsLXGppO6kF79qqrWvpCO0LHAhZX8lR4syYP06_Y93JMvJ64_CtVlyYb79_fjF1L8_7j4ko_bTzkva5_ANjE2esshekNAo_ArQkCHexs_MPFrK6U4M21YN2nHkoT-Fsj0OyiZ3GBM89fRzZolsm-KqhuXxH9xV028KSxiCbT43LFRCD9SFjmQrGLqRNV7xtZkSeyvq-RwmvIkywPK7e2xIfpJpp6d6RUpJZC85ky4-FoK-SYpm8C5pBKwR37_2XV0fs7AFt6ixU-301wtHDSAcdFg6acbzlLsa-iyJnF6yoldnit5s5Jq9J6hRsZd9IfflitGBSB0Z6DhBQEDaMMG0--_wiMN68A9YoPq9dVdLibEoSY1ye7mFp_3oUVLRKvH5Fi_hGwTOZ3MANOnlvM1_158pvtApChLZBg2bMV65EmAQ53IIcVZMxqDDYX1KGqFf39Ds6EeyN1I_IQrCSgpxFiHZRtd.QWdXTJHhURgkfQC61FJjVQ");

        String data = jwe.header().toString();

        assertThat(data).isEqualTo("eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0");
    }

    @Test
    void givenJWE_thenAlgorithmCorrect() throws ParseException {
        JWE jwe = JWEFactory.parse("eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0..FJze_l4riv2Xp-wl.HtXmzfHH5FoStStIaUGAg5x03tZSkkfcuQVEhNZz5awdQ6UKduXie4iN10qG6hPAG9snH8peYwhHynkrVmW1grzWCTgSzwyWKUqfOL3J8iybvqDvTqAD4_UN3M59rcgVANNc3qQ3YupeSYC7H1H6RzMD-EHvJ51t5biUc1B0YCvFfi7HP5h6ArIUsLXGppO6kF79qqrWvpCO0LHAhZX8lR4syYP06_Y93JMvJ64_CtVlyYb79_fjF1L8_7j4ko_bTzkva5_ANjE2esshekNAo_ArQkCHexs_MPFrK6U4M21YN2nHkoT-Fsj0OyiZ3GBM89fRzZolsm-KqhuXxH9xV028KSxiCbT43LFRCD9SFjmQrGLqRNV7xtZkSeyvq-RwmvIkywPK7e2xIfpJpp6d6RUpJZC85ky4-FoK-SYpm8C5pBKwR37_2XV0fs7AFt6ixU-301wtHDSAcdFg6acbzlLsa-iyJnF6yoldnit5s5Jq9J6hRsZd9IfflitGBSB0Z6DhBQEDaMMG0--_wiMN68A9YoPq9dVdLibEoSY1ye7mFp_3oUVLRKvH5Fi_hGwTOZ3MANOnlvM1_158pvtApChLZBg2bMV65EmAQ53IIcVZMxqDDYX1KGqFf39Ds6EeyN1I_IQrCSgpxFiHZRtd.QWdXTJHhURgkfQC61FJjVQ");

        String algorithm = jwe.header().algorithm();

        assertThat(algorithm).isEqualTo("dir");
    }

    @Test
    void givenJWE_thenKeyIdCorrect() throws ParseException {
        JWE jwe = JWEFactory.parse("eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBMV81Iiwia2lkIjoidGVzdCJ9.tgnoI6TehvT1_0xRqtIQAnQ2fKFzH0C2E22uL53WkILw1DeppA23yCHwIyH0ZgiUtrKBfRyYkZiZ-1RSvZuk-_19hJGaDqygEzVHqaF7scJI1luNu7Ne7wI6WCeLk_Izlv_C8ymK9iV6xpNG9XYjK7rCgB2t31LBqHwtDQ2Ri1_wOVEm4xfNwrhR5ahaXENS4QUk-tGzxjj2Q3PNq6rOr3fHMq6YWShKKBzGienwwF7hnGXgL6cai_Qq2R7bB4fHpoSlzhR9dilgrvrtGSjsfaXB_vsckFZPg5xi1625LijqjB6uCzTDjNZQXgWI5pOwY4zg2afPdspIcEG0ILxtRA.m0dAYlhboIHQVObA.a6SEvaZxpPjm9_y0CySOHB3YL6j9GMMWFY_I2PdX0hNqBw9sT_d-wUGNgqwgD9ILamCnCgdQfbfGiU-pxE0uDTq9cM4ak4YZEIOvmkM4VTncZNBcbrFiXcmxc4vYcd70s48KQFvUhSbhK8c662b_4XThiojhN3n2cPrYx7dxcR7EuYmjwfOVXfyl7ZwLf3y_g_rwjzj7ujRQchUWkCsAOABURvmTOhiCwXxDtG0qE0zFJlsnbbFRbbaySMGtOT7VyLQcHg.tzH2t8SCnt75dwp2LcBHuA");

        String algorithm = jwe.header().keyId();

        assertThat(algorithm).isEqualTo("test");
    }
}