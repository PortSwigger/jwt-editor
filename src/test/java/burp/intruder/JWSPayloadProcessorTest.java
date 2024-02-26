package burp.intruder;

import burp.api.montoya.MontoyaExtension;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.FakeByteArray;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.intruder.FakePayloadProcessingResult;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;
import com.blackberry.jwteditor.model.keys.KeysModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.stubbing.Answer;

import static burp.api.montoya.intruder.FakePayloadData.payloadData;
import static burp.api.montoya.intruder.PayloadProcessingAction.USE_PAYLOAD;
import static burp.api.montoya.logging.StubLogging.LOGGING;
import static burp.intruder.FuzzLocation.HEADER;
import static burp.intruder.FuzzLocation.PAYLOAD;
import static burp.intruder.IntruderConfigBuilder.intruderConfig;
import static com.blackberry.jwteditor.KeysModelBuilder.keysModel;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static com.nimbusds.jose.JWSAlgorithm.RS512;
import static data.PemData.RSA1024Private;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MontoyaExtension.class)
class JWSPayloadProcessorTest {
    private static final KeysModel EMPTY_KEYS_MODEL = keysModel().build();
    private static final String KEY_ID = "id";

    @BeforeEach
    void configureMocks() {
        MontoyaObjectFactory factory = ObjectFactoryLocator.FACTORY;

        when(factory.usePayload(any(ByteArray.class))).thenAnswer((Answer<PayloadProcessingResult>) i ->
                new FakePayloadProcessingResult(i.getArgument(0, ByteArray.class)));

        when(factory.byteArray(anyString())).thenAnswer((Answer<ByteArray>) i ->
                new FakeByteArray(i.getArgument(0, String.class)));
    }

    @Test
    void givenBaseValueNotJWS_whenPayloadProcessed_thenPayloadLeftUnchanged() {
        String baseValue = "isogeny";
        PayloadData payloadData = payloadData().withBaseValue(baseValue).build();
        IntruderConfig intruderConfig = intruderConfig().withFuzzParameter("role").withFuzzLocation(PAYLOAD).build();

        JWSPayloadProcessor processor = new JWSPayloadProcessor(intruderConfig, LOGGING, EMPTY_KEYS_MODEL);
        PayloadProcessingResult result = processor.processPayload(payloadData);

        assertThat(result.action()).isEqualTo(USE_PAYLOAD);
        assertThat(result.processedPayload().toString()).isEqualTo(baseValue);
    }

    @Test
    void givenBaseValueJWSAndFuzzParameterNotPresent_whenPayloadProcessed_thenPayloadLeftUnchanged() {
        String baseValue = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        PayloadData payloadData = payloadData().withBaseValue(baseValue).build();
        IntruderConfig intruderConfig = intruderConfig().withFuzzParameter("role").withFuzzLocation(PAYLOAD).build();

        JWSPayloadProcessor processor = new JWSPayloadProcessor(intruderConfig, LOGGING, EMPTY_KEYS_MODEL);
        PayloadProcessingResult result = processor.processPayload(payloadData);

        assertThat(result.action()).isEqualTo(USE_PAYLOAD);
        assertThat(result.processedPayload().toString()).isEqualTo(baseValue);
    }

    @Test
    void givenBaseValueJWSAndFuzzParameterPresentInWrongContext_whenPayloadProcessed_thenPayloadLeftUnchanged() {
        String baseValue = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        PayloadData payloadData = payloadData().withBaseValue(baseValue).build();
        IntruderConfig intruderConfig = intruderConfig().withFuzzParameter("alg").withFuzzLocation(PAYLOAD).build();

        JWSPayloadProcessor processor = new JWSPayloadProcessor(intruderConfig, LOGGING, EMPTY_KEYS_MODEL);
        PayloadProcessingResult result = processor.processPayload(payloadData);

        assertThat(result.action()).isEqualTo(USE_PAYLOAD);
        assertThat(result.processedPayload().toString()).isEqualTo(baseValue);
    }

    @Test
    void givenBaseValueJWSAndFuzzParameterPresentInHeader_whenPayloadProcessed_thenPayloadModified() {
        String baseValue = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        PayloadData payloadData = payloadData().withBaseValue(baseValue).withCurrentPayload("RS256").build();
        IntruderConfig intruderConfig = intruderConfig().withFuzzParameter("alg").withFuzzLocation(HEADER).build();

        JWSPayloadProcessor processor = new JWSPayloadProcessor(intruderConfig, LOGGING, EMPTY_KEYS_MODEL);
        PayloadProcessingResult result = processor.processPayload(payloadData);

        assertThat(result.action()).isEqualTo(USE_PAYLOAD);
        assertThat(result.processedPayload().toString()).isEqualTo("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
    }

    @Test
    void givenBaseValueJWSAndFuzzParameterPresentInPayload_whenPayloadProcessed_thenPayloadModified() {
        String baseValue = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        PayloadData payloadData = payloadData().withBaseValue(baseValue).withCurrentPayload("emanon").build();
        IntruderConfig intruderConfig = intruderConfig().withFuzzParameter("name").withFuzzLocation(PAYLOAD).build();

        JWSPayloadProcessor processor = new JWSPayloadProcessor(intruderConfig, LOGGING, EMPTY_KEYS_MODEL);
        PayloadProcessingResult result = processor.processPayload(payloadData);

        assertThat(result.action()).isEqualTo(USE_PAYLOAD);
        assertThat(result.processedPayload().toString()).isEqualTo("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImVtYW5vbiIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
    }

    @Test
    void givenBaseValueJWSAndFuzzParameterPresentInPayload_whenSigningKeyLoadedButResignOff_thenPayloadModifiedButNotResigned() {
        String baseValue = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        PayloadData payloadData = payloadData().withBaseValue(baseValue).withCurrentPayload("emanon").build();
        KeysModel keysModel = keysModel().withRSAKey(RSA1024Private, KEY_ID).build();
        IntruderConfig intruderConfig = intruderConfig()
                .withFuzzParameter("name")
                .withFuzzLocation(PAYLOAD)
                .withSigningKeyId(KEY_ID)
                .withSigningAlgorithm(RS512)
                .build();

        JWSPayloadProcessor processor = new JWSPayloadProcessor(intruderConfig, LOGGING, keysModel);
        PayloadProcessingResult result = processor.processPayload(payloadData);

        assertThat(result.action()).isEqualTo(USE_PAYLOAD);
        assertThat(result.processedPayload().toString()).isEqualTo("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImVtYW5vbiIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
    }

    @Test
    void givenBaseValueJWSAndFuzzParameterPresentInPayload_whenResignOnButUnknownSigningKeyConfigured_thenPayloadModifiedButNotResigned() {
        String baseValue = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        PayloadData payloadData = payloadData().withBaseValue(baseValue).withCurrentPayload("emanon").build();
        KeysModel keysModel = keysModel().withRSAKey(RSA1024Private, KEY_ID).build();
        IntruderConfig intruderConfig = intruderConfig()
                .withFuzzParameter("name")
                .withFuzzLocation(PAYLOAD)
                .withSigningKeyId("rogue")
                .withSigningAlgorithm(RS512)
                .withResigning(true)
                .build();

        JWSPayloadProcessor processor = new JWSPayloadProcessor(intruderConfig, LOGGING, keysModel);
        PayloadProcessingResult result = processor.processPayload(payloadData);

        assertThat(result.action()).isEqualTo(USE_PAYLOAD);
        assertThat(result.processedPayload().toString()).isEqualTo("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImVtYW5vbiIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
    }

    @Test
    void givenBaseValueJWSAndFuzzParameterPresentInPayload_whenResignOnAndSigningKeyPresentAndAlgorithmUnchanged_thenPayloadModifiedAndResignedButAlgUnchanged() {
        String baseValue = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.LX5A6Hu00jlQ2n8s1SoVL4BEPjMiF1zrEs3qRtV08sbmsqxXV8bc8LarGm8YZj2OuXWL7aOkdBc9ezOBi5bjxsrtiUmwo5VWlU5Y6PXqGwH5v7w0kpRckdd0IA3nbrR2SyLQ1L1pQJk2PzoCvEpspBPMxtIyrK5MTep3Yx1Xn3aiw3aE1cHzOwK0xBIg-RW5qK5PwPa4H8T7eOOSMytS6N4AiZbeiIVHBWxmjrdp8AuC_fmfM1TQA_O8gK_1QkK3jPWkmbbtb48ut6dxz3H_gvPkPzsRE96nQ1qcOlbJjN0URcR2Tc1ACwZO4VpY4gujo_LwTsLiKQcmq0glFA3SIw";
        PayloadData payloadData = payloadData().withBaseValue(baseValue).withCurrentPayload("emanon").build();
        KeysModel keysModel = keysModel().withRSAKey(RSA1024Private, KEY_ID).build();
        IntruderConfig intruderConfig = intruderConfig()
                .withFuzzParameter("name")
                .withFuzzLocation(PAYLOAD)
                .withSigningKeyId(KEY_ID)
                .withSigningAlgorithm(RS512)
                .withResigning(true)
                .build();

        JWSPayloadProcessor processor = new JWSPayloadProcessor(intruderConfig, LOGGING, keysModel);
        PayloadProcessingResult result = processor.processPayload(payloadData);

        assertThat(result.action()).isEqualTo(USE_PAYLOAD);
        assertThat(result.processedPayload().toString()).isEqualTo("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImVtYW5vbiIsImlhdCI6MTUxNjIzOTAyMn0.poPOxqjqp-CnC2b7eaf2QvfvAfawzp6k-P1QECIHN7KCTnFIlQbiJC4ZtLPH_0-o3HQcUGZbib3m1CVWeY21FIUTVUmOyjU8XuBohtBXRlXoaKXVWibrm5YiLC3yNQz5uAF-gdBB8ybvsmetK7JIZ8UvQdJ3mdvlAAW-3xFv8fs");
    }

    @Test
    void givenBaseValueJWSAndFuzzParameterPresentInPayload_whenResignOnAndSigningKeyPresentAndAlgorithmChanged_thenPayloadAndAlgModifiedAndResigned() {
        String baseValue = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImNyZXMiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        PayloadData payloadData = payloadData().withBaseValue(baseValue).withCurrentPayload("emanon").build();
        KeysModel keysModel = keysModel().withRSAKey(RSA1024Private, KEY_ID).build();
        IntruderConfig intruderConfig = intruderConfig()
                .withFuzzParameter("name")
                .withFuzzLocation(PAYLOAD)
                .withSigningKeyId(KEY_ID)
                .withSigningAlgorithm(RS256)
                .withResigning(true)
                .build();

        JWSPayloadProcessor processor = new JWSPayloadProcessor(intruderConfig, LOGGING, keysModel);
        PayloadProcessingResult result = processor.processPayload(payloadData);

        assertThat(result.action()).isEqualTo(USE_PAYLOAD);
        assertThat(result.processedPayload().toString()).isEqualTo("eyJraWQiOiJjcmVzIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImVtYW5vbiIsImlhdCI6MTUxNjIzOTAyMn0.qZw9QLyX5NAxBioegUsiBoWVpVShdy1EGHwwgOtknyVXhXqQDbXt15IYUkj66_dDIGNuZ76g_BdJLy9V9qG-sTbQgsLykbfLfdqelNhOsw-c_gs7eJPK0DYaYmBZNJayD5EJoOTF0Vs0AR2Rlnhf1PeoK04HZfJhoDS39gs4hRU");
    }
}