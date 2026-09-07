package com.blackberry.jwteditor.operations;

import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.jose.JWSFactory;
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.JWKKeyFactory;
import com.blackberry.jwteditor.pem.PemKey.NewLineStrategy;
import com.blackberry.jwteditor.utils.PEMUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Base64;
import java.util.stream.Stream;

import static com.blackberry.jwteditor.pem.PemKey.NewLineStrategy.*;
import static com.nimbusds.jose.JWSAlgorithm.HS256;
import static java.lang.System.lineSeparator;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class HmacKeyConfusionAttackTest {
    private static final String JWS = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU0NzcyOTY2MiwiZXhwIjoxNTQ3Nzk5OTk5LCJkYXRhIjp7Ik5DQyI6InRlc3QifX0.";
    private static final String EXPECTED_JWS_SIGNATURE_LINUX_MACOS_TRAILING_NEWLINE = "2zobdg7sgeApcEaR9ngMTRZT1dkWiMJOWYkelzQu5Z8";
    private static final String EXPECTED_JWS_SIGNATURE_WINDOWS_TRAILING_NEWLINE = "ckEZE2Hg_vO--9cbwz1dKvtfx7k-RHOc3EzwGBSQ_zc=";
    private static final String EXPECTED_JWS_SIGNATURE_LINUX_MACOS= "AYASLtLK3T8lMA7v5iJ8Crxjxj6Gh9mPm9OUDcgEws8=";
    private static final String EXPECTED_JWS_SIGNATURE_WINDOWS = "bC1E_nUSPZZrdo3CUwHL86CsiDAe5kwkJW81BVuwGus=";
    private static final String RSA_KEY_PEM = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqi8TnuQBGXOGx/Lfn4JF
            NYOH2V1qemfs83stWc1ZBQFCQAZmUr/sgbPypYzy229pFl6bGeqpiRHrSufHug7c
            1LCyalyUEP+OzeqbEhSSuUss/XyfzybIusbqIDEQJ+Yex3CdgwC/hAF3xptV/2t+
            H6y0Gdh1weVKRM8+QaeWUxMGOgzJYAlUcRAP5dRkEOUtSKHBFOFhEwNBXrfLd76f
            ZXPNgyN0TzNLQjPQOy/tJ/VFq8CQGE4/K5ElRSDlj4kswxonWXYAUVxnqRN1LGHw
            2G5QRE2D13sKHCC8ZrZXJzj67Hrq5h2SADKzVzhA8AW3WZlPLrlFT3t1+iZ6m+aF
            KwIDAQAB
            -----END PUBLIC KEY-----""";

    private static Stream<Arguments> data() {
        return Stream.of(
                arguments(SYSTEM_DEFAULT, "\n".equals(lineSeparator()) ? EXPECTED_JWS_SIGNATURE_LINUX_MACOS_TRAILING_NEWLINE : EXPECTED_JWS_SIGNATURE_WINDOWS_TRAILING_NEWLINE),
                arguments(LINUX_MACOS, EXPECTED_JWS_SIGNATURE_LINUX_MACOS_TRAILING_NEWLINE),
                arguments(WINDOWS, EXPECTED_JWS_SIGNATURE_WINDOWS_TRAILING_NEWLINE),
                arguments(LINUX_MACOS_NO_TRAILING_LINE, EXPECTED_JWS_SIGNATURE_LINUX_MACOS),
                arguments(WINDOWS_NO_TRAILING_LINE, EXPECTED_JWS_SIGNATURE_WINDOWS)
        );
    }

    @MethodSource("data")
    @ParameterizedTest
    void testHMACKeyConfusion(NewLineStrategy newLineStrategy, String expectedSignature) throws Exception {
        JWS jws = JWSFactory.parse(JWS);
        JWKKey key = JWKKeyFactory.from(PEMUtils.pemToRSAKey(RSA_KEY_PEM));

        JWS modifiedJWS  = HmacKeyConfusionAttack.attack(jws, key, HS256, newLineStrategy);

        assertThat(modifiedJWS.signature().data()).isEqualTo(Base64.getUrlDecoder().decode(expectedSignature));
    }
}
