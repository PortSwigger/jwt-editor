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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.text.ParseException;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class JWSHeadersTest {

    @Test
    void givenJWSWithCompactHeader_thenHeaderIsCompact() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        assertThat(jws.header().isCompact()).isTrue();
    }

    @Test
    void givenJWSWithNonCompactHeader_thenHeaderIsNotCompact() throws ParseException {
        JWS jws = JWSFactory.parse("ewogICAgInR5cCI6ICJKV1QiLAogICAgImFsZyI6ICJub25lIgp9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        assertThat(jws.header().isCompact()).isFalse();
    }

    @Test
    void givenJWSWithCompactHeader_thenPrettyPrintDecodedHeaderIsCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        String decodedHeader = jws.header().decodeAndPrettyPrint();

        assertThat(decodedHeader).isEqualTo("""
                {
                    "typ": "JWT",
                    "alg": "none"
                }""");
    }

    @Test
    void givenJWS_thenDecodedHeaderIsCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        String decodedHeader = jws.header().decoded();

        assertThat(decodedHeader).isEqualTo("{\"typ\":\"JWT\",\"alg\":\"none\"}");
    }

    @Test
    void givenJWS_thenEncodedHeaderIsCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        Base64URL encodedHeader = jws.header().encoded();

        assertThat(encodedHeader).isEqualTo(new Base64URL("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0"));
    }

    @Test
    void givenJWS_thenHeaderJsonIsCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        JSONObject headerJson = jws.header().json();

        assertThat(headerJson.similar(new JSONObject("{\"typ\":\"JWT\",\"alg\":\"none\"}"))).isTrue();
    }

    @Test
    void givenJWS_thenHeaderSerializationCorrect() throws ParseException {
        JWS jws = JWSFactory.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.");

        String data = jws.header().toString();

        assertThat(data).isEqualTo("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0");
    }

    private static Stream<Arguments> algorithmData() {
        return Stream.of(
                arguments("eyJraWQiOiI4NTVmNmJlZi1jNWUwLTRjYWYtODU2OS03NjhmN2U5OTI1YzEifQ.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTczNTY0OTU1OCwic3ViIjoid2llbmVyIn0.qxz-0rVrVft-LIQO-QKgKL6tC1OdhHO7s8-SupOdp1XIP1T1yBE-G6G34e5h1fi10uY1u2W_yHLfmWVwhaPLe6ckPTiq5wivlUqhbVocSo6vKb6vFOeb3Q3fP6bI_gBDvhDYDwszfrMm69lwNBYYn2cAXlnm-YaJ-XHt-M_99loSxQFo-I3OWclzChuOoCPkEXQSbZ5CWuNmLYi37T7JEj5f8YHWI92rQOo0_Gby2KITToOHSs1WowXZy5UIM0ByNGNzC9w6MhdLD5GdAk2Mdt8dyryH9rg_RPAV6eJHhxkxiR8wRui7VbDEIx5GISubRzqgLqAuMJ1zvJ8PnH1qNQ", ""),
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "HS256"),
                arguments("eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.bQTnz6AuMJvmXXQsVPrxeQNvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311JHuh", "HS384"),
                arguments("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VFb0qJ1LRg_4ujbZoRMXnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxtHWKa64zDl2ofkT8F6jBt_K4riU-fPg", "HS512"),
                arguments("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ", "RS256"),
                arguments("eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJhh994RAPzCG0hmQ", "RS384"),
                arguments("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.jYW04zLDHfR1v7xdrW3lCGZrMIsVe0vWCfVkN2DRns2c3MN-mcp_-RE6TN9umSBYoNV-mnb31wFf8iun3fB6aDS6m_OXAiURVEKrPFNGlR38JSHUtsFzqTOj-wFrJZN4RwvZnNGSMvK3wzzUriZqmiNLsG8lktlEn6KA4kYVaM61_NpmPHWAjGExWv7cjHYupcjMSmR8uMTwN5UuAwgW6FRstCJEfoxwb0WKiyoaSlDuIiHZJ0cyGhhEmmAPiCwtPAwGeaL1yZMcp0p82cpTQ5Qb-7CtRov3N4DcOHgWYk6LomPR5j5cCkePAz87duqyzSMpCB0mCOuE3CU2VMtGeQ", "RS512"),
                arguments("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA", "ES256"),
                arguments("eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VUPWQZuClnkFbaEKCsPy7CZVMh5wxbCSpaAWFLpnTe9J0--PzHNeTFNXCrVHysAa3eFbuzD8_bLSsgTKC8SzHxRVSj5eN86vBPo_1fNfE7SHTYhWowjY4E_wuiC13yoj", "ES384"),
                arguments("eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AbVUinMiT3J_03je8WTOIl-VdggzvoFgnOsdouAs-DLOtQzau9valrq-S6pETyi9Q18HH-EuwX49Q7m3KC0GuNBJAc9Tksulgsdq8GqwIqZqDKmG7hNmDzaQG1Dpdezn2qzv-otf3ZZe-qNOXUMRImGekfQFIuH_MjD2e8RZyww6lbZk", "ES512"),
                arguments("eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.iOeNU4dAFFeBwNj6qdhdvm-IvDQrTa6R22lQVJVuWJxorJfeQww5Nwsra0PjaOYhAMj9jNMO5YLmud8U7iQ5gJK2zYyepeSuXhfSi8yjFZfRiSkelqSkU19I-Ja8aQBDbqXf2SAWA8mHF8VS3F08rgEaLCyv98fLLH4vSvsJGf6ueZSLKDVXz24rZRXGWtYYk_OYYTVgR1cg0BLCsuCvqZvHleImJKiWmtS0-CymMO4MMjCy_FIl6I56NqLE9C87tUVpo1mT-kbg5cHDD8I7MjCW5Iii5dethB4Vid3mZ6emKjVYgXrtkOQ-JyGMh6fnQxEFN1ft33GX2eRHluK9eg", "PS256"),
                arguments("eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.Lfe_aCQme_gQpUk9-6l9qesu0QYZtfdzfy08w8uqqPH_gnw-IVyQwyGLBHPFBJHMbifdSMxPjJjkCD0laIclhnBhowILu6k66_5Y2z78GHg8YjKocAvB-wSUiBhuV6hXVxE5emSjhfVz2OwiCk2bfk2hziRpkdMvfcITkCx9dmxHU6qcEIsTTHuH020UcGayB1-IoimnjTdCsV1y4CMr_ECDjBrqMdnontkqKRIM1dtmgYFsJM6xm7ewi_ksG_qZHhaoBkxQ9wq9OVQRGiSZYowCp73d2BF3jYMhdmv2JiaUz5jRvv6lVU7Quq6ylVAlSPxeov9voYHO1mgZFCY1kQ", "PS384"),
                arguments("eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.J5W09-rNx0pt5_HBiydR-vOluS6oD-RpYNa8PVWwMcBDQSXiw6-EPW8iSsalXPspGj3ouQjAnOP_4-zrlUUlvUIt2T79XyNeiKuooyIFvka3Y5NnGiOUBHWvWcWp4RcQFMBrZkHtJM23sB5D7Wxjx0-HFeNk-Y3UJgeJVhg5NaWXypLkC4y0ADrUBfGAxhvGdRdULZivfvzuVtv6AzW6NRuEE6DM9xpoWX_4here-yvLS2YPiBTZ8xbB3axdM99LhES-n52lVkiX5AWg2JJkEROZzLMpaacA_xlbUz_zbIaOaoqk8gB5oO7kI6sZej3QAdGigQy-hXiRnW_L98d4GQ", "PS512")
        );
    }

    @ParameterizedTest
    @MethodSource("algorithmData")
    void givenJWS_thenAlgorithmCorrect(String data, String expectedAlgorithm) throws ParseException {
        JWS jws = JWSFactory.parse(data);

        String algorithm = jws.header().algorithm();

        assertThat(algorithm).isEqualTo(expectedAlgorithm);
    }
}