package com.blackberry.jwteditor.view.config;

import burp.intruder.IntruderConfig;
import com.blackberry.jwteditor.model.keys.KeysModel;
import org.junit.jupiter.api.Test;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static org.assertj.core.api.Assertions.assertThat;

class IntruderConfigModelFromJsonTest {
    private static final String KEYS_JSON = """
            [
                {"kty":"EC","d":"R7xUBrtHikGBXsJkDekdUxWWC2YhYMKTDXILREc4_7s","crv":"P-256","kid":"1","x":"Kxyedi_DE6wZdC1shMeYVx9IvSXl14RRp_Z5tZjBodo","y":"UXtt70JCve0c_puZsjyTHtLD6xfBvoI3fVoh9WzhH-M"},
                {"kty":"EC","crv":"P-256","kid":"2","x":"Kxyedi_DE6wZdC1shMeYVx9IvSXl14RRp_Z5tZjBodo","y":"UXtt70JCve0c_puZsjyTHtLD6xfBvoI3fVoh9WzhH-M"}
            ]""";

    @Test
    void givenKeysLoadedJson_butNoSelectedKey_whenGetSigningKeyId_thenFirstKeyIdReturned() throws Exception {
        IntruderConfigModel model = new IntruderConfigModel(KeysModel.parse(KEYS_JSON), new IntruderConfig());

        assertThat(model.signingKeyId()).isEqualTo("1");
    }

    @Test
    void givenKeysLoadedJson_butNoSelectedKey_whenGetSigningAlgorithms_thenFirstKeysAlgorithmsReturned() throws Exception {
        IntruderConfigModel model = new IntruderConfigModel(KeysModel.parse(KEYS_JSON), new IntruderConfig());

        assertThat(model.signingAlgorithms()).containsExactly(ES256);
    }

    @Test
    void givenKeysLoadedJson_butNoSelectedKey_whenGetSigningAlgorithm_thenFirstAlgorithmReturned() throws Exception {
        IntruderConfigModel model = new IntruderConfigModel(KeysModel.parse(KEYS_JSON), new IntruderConfig());

        assertThat(model.signingAlgorithm()).isEqualTo(ES256);
    }
}