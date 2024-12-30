/*
Author : Dolph Flynn

Copyright 2023 Dolph Flynn

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

package burp.scanner;

import burp.api.montoya.MontoyaExtension;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.FakeByteArray;
import burp.api.montoya.core.FakeRange;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.FakeHttpRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.jose.JWSFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.stubbing.Answer;

import java.util.List;
import java.util.stream.Stream;

import static burp.api.montoya.http.FakeHttpRequestResponse.requestResponse;
import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@ExtendWith(MontoyaExtension.class)
class JWSHeaderInsertionPointTest {
    private static final String TEST_JWS = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    private static final String WEAPONIZED_JWS = "eyJraWQiOiIuLi9ldGMvcGFzc3dkIiwidHlwIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    private static final String PAYLOAD = "../etc/passwd";

    @BeforeAll
    static void setUpMockFactory() {
        when(FACTORY.byteArray(any(byte[].class))).thenAnswer((Answer<ByteArray>) c -> new FakeByteArray((byte[]) c.getArgument(0)));
        when(FACTORY.byteArray(anyString())).thenAnswer((Answer<ByteArray>) c -> new FakeByteArray((String) c.getArgument(0)));
        when(FACTORY.httpRequest(any(), any(ByteArray.class))).thenAnswer((Answer<HttpRequest>) c -> new FakeHttpRequest(c.getArgument(0), c.getArgument(1)));
        when(FACTORY.range(anyInt(), anyInt())).thenAnswer((Answer<Range>) c -> new FakeRange(c.getArgument(0), c.getArgument(1)));
    }

    static Stream<Arguments> baseRequestData() {
        return Stream.of(
                arguments(TEST_JWS, WEAPONIZED_JWS),
                arguments("012345678 " + TEST_JWS + " 9abcdef", "012345678 " + WEAPONIZED_JWS + " 9abcdef"),
                arguments(TEST_JWS + " 0123456789abcdef", WEAPONIZED_JWS + " 0123456789abcdef"),
                arguments("0123456789abcdef " + TEST_JWS, "0123456789abcdef " + WEAPONIZED_JWS)
        );
    }

    @ParameterizedTest
    @MethodSource("baseRequestData")
    void givenJWSInBaseRequest_whenRequestWithPayloadBuilt_thenAttackRequestCorrect(String baseRequest, String expectedAttackRequest) {
        AuditInsertionPoint insertionPoint = insertionPointForData(baseRequest);
        ByteArray payloadBytes = ByteArray.byteArray(PAYLOAD);

        HttpRequest httpRequest = insertionPoint.buildHttpRequestWithPayload(payloadBytes);
        ByteArray attackRequest = httpRequest.toByteArray();

        assertThat(attackRequest.toString()).isEqualTo(expectedAttackRequest);
    }

    @Test
    void givenJWSWithBackslash_whenPayloadInserted_thenHeaderCorrect() throws Exception {
        AuditInsertionPoint insertionPoint = insertionPointForData("eyJraWQiOiIvZGV2L251bGwiLCJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.6mbgcHRELcZ3kLuiKcCit2ae2XNXBDcVXuS9yHydq2KCnvxgR7JLC1fzeJwv5a7KIOqoa780na3LNEhCaXPbLw");
        ByteArray payloadBytes = ByteArray.byteArray(PAYLOAD);

        HttpRequest httpRequest = insertionPoint.buildHttpRequestWithPayload(payloadBytes);
        ByteArray attackRequest = httpRequest.toByteArray();

        JWS attackJws = JWSFactory.parse(attackRequest.toString());
        assertThat(attackJws.header().decoded()).isEqualTo("{\"kid\":\"../etc/passwd\",\"typ\":\"JWT\",\"alg\":\"ES256\"}");
    }

    @Test
    void givenKeyIdentifierAsHeaderParameter_thenNameCorrect() {
        AuditInsertionPoint insertionPoint = insertionPointForData(TEST_JWS);

        assertThat(insertionPoint.name()).isEqualTo("JWS header 'kid'");
    }

    @Test
    void givenJWSInBaseRequest_thenBaseValueCorrect() {
        AuditInsertionPoint insertionPoint = insertionPointForData(TEST_JWS);

        assertThat(insertionPoint.baseValue()).isEqualTo(TEST_JWS);
    }

    static Stream<Arguments> highlightsData() {
        return Stream.of(
                arguments(TEST_JWS, 0, 185),
                arguments("012345678 " + TEST_JWS + " 9abcdef", 10, 195),
                arguments(TEST_JWS + " 0123456789abcdef", 0, 185),
                arguments("0123456789abcdef " + TEST_JWS, 17, 202)
        );
    }

    @ParameterizedTest
    @MethodSource("highlightsData")
    void givenJWSInBaseRequest_thenIssueHighlightsCorrect(String baseRequest, int highlightStart, int highlightEnd) {
        AuditInsertionPoint insertionPoint = insertionPointForData(baseRequest);
        ByteArray payloadBytes = ByteArray.byteArray(PAYLOAD);

        List<Range> highlights = insertionPoint.issueHighlights(payloadBytes);

        assertThat(highlights).containsExactly(new FakeRange(highlightStart, highlightEnd));
    }

    private static AuditInsertionPoint insertionPointForData(String data) {
        ScannerConfig config = new ScannerConfig();
        config.setEnableHeaderJWSInsertionPointLocation(true);
        config.setInsertionPointLocationParameterName("kid");

        JWSHeaderInsertionPointProvider insertionPointProvider = new JWSHeaderInsertionPointProvider(config);

        HttpRequestResponse requestResponse = requestResponse().withRequest(data).build();

        List<AuditInsertionPoint> insertionPoints = insertionPointProvider.provideInsertionPoints(requestResponse);
        assertThat(insertionPoints).hasSize(1);

        return insertionPoints.getFirst();
    }
}
