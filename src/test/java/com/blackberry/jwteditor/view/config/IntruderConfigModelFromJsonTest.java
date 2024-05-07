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
    private static final String NO_SIGNING_KEYS_JSON = """
            [
                {"kty":"RSA","x5t#S256":"AbulYyEMgASQ_N8S_FiWgoMNeT0q4Pu5rMKFc1m9YDs","e":"AQAB","use":"sig","x5t":"9f_KFyu6DwwzxKC5nz76dTbCRgE","kid":"njJgWzxMQSarMfvxK5bJ6ejo1AH-DmvXNCdsbfnv-cY","x5c":["MIIClTCCAX0CBgFydTAgQjANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANTQlAwHhcNMjAwNjAyMTMxODA3WhcNMzAwNjAyMTMxOTQ3WjAOMQwwCgYDVQQDDANTQlAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOTIcesYvvrvYqf23U+SCRJ6XHjUvvx3RVNTsgpxqEflJvHo1Z/PBiNbh7ckDApo8gt7SvSnsDG+zYrH8bcPWMcPnvf42YMjCY3SmtzjHWpw6z8nEbNMk3zqE4HjSdwYiS1+ndRt+7u0lFfoJEC+M3tWOukxHgaI+NSQfoHE5Ncbm0cqnuQrFu0oQbh2gXlFefB9DYbgS6FGE1mb6S7z358BZ+3gqoCf3snbYPyYa38QADD0va9aTw1zPmAjOvXubcEMd57uUwtXfkMgw3NNjr5R8gZYY9/Ueim8zB4oXCQTs03M9g8LlwVR827x0pB2W/r1SMH0rtkkYIOO8yy4gnAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJfuyot3Z63EdzNwVusXli5xe9eH7IumNXEW6WEu+Q7aoJ+22FiIyika2VaiDp+fHJ2XFG5C+L+pKPRaW89C41N2nyy9CywRnE4jYbjbSUAC6cIFNQ1nSmNTh1hass7mbBJiSvH6qSbnXvmAfelnbl5uNbviX0omrAXVm2l+bAZ+uT4Sxy8quqRtgyfP41cYOq5WVvmQ8KfkiG6Z9Dh3y2H3P25nAixGWN8SdL90OI7flOXp8d0Qo6trTacGmSV5+rR2K6vzBSBWZToh36zV9l47y4oxk/rkOt1uBeEzLV08yS3T8KpndiX/i3tKd86SEo4yXZyEyHCzXA3BIZgkYt4="],"alg":"RS256","n":"zkyHHrGL7672Kn9t1PkgkSelx41L78d0VTU7IKcahH5Sbx6NWfzwYjW4e3JAwKaPILe0r0p7Axvs2Kx_G3D1jHD573-NmDIwmN0prc4x1qcOs_JxGzTJN86hOB40ncGIktfp3Ubfu7tJRX6CRAvjN7VjrpMR4GiPjUkH6BxOTXG5tHKp7kKxbtKEG4doF5RXnwfQ2G4EuhRhNZm-ku89-fAWft4KqAn97J22D8mGt_EAAw9L2vWk8Ncz5gIzr17m3BDHee7lMLV35DIMNzTY6-UfIGWGPf1HopvMweKFwkE7NNzPYPC5cFUfNu8dKQdlv69UjB9K7ZJGCDjvMsuIJw"}
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

    @Test
    void givenKeysLoadedJson_butNoSigningKeysPresent_whenGetSigningAlgorithms_thenNoAlgorithmsReturned() throws Exception {
        IntruderConfig intruderConfig = new IntruderConfig();
        intruderConfig.setSigningKeyId("27f68f1c-0b06-4612-8e98-75ac1738ebcf");
        IntruderConfigModel model = new IntruderConfigModel(KeysModel.parse(NO_SIGNING_KEYS_JSON), intruderConfig);

        assertThat(model.signingAlgorithms()).isEmpty();
    }

    @Test
    void givenKeysLoadedJson_butNoSigningKeysPresent_whenGetSigningAlgorithm_thenNullReturned() throws Exception {
        IntruderConfig intruderConfig = new IntruderConfig();
        intruderConfig.setSigningKeyId("27f68f1c-0b06-4612-8e98-75ac1738ebcf");
        IntruderConfigModel model = new IntruderConfigModel(KeysModel.parse(NO_SIGNING_KEYS_JSON), intruderConfig);

        assertThat(model.signingAlgorithm()).isNull();
    }
}