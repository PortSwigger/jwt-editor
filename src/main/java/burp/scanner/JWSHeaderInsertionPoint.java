package burp.scanner;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.blackberry.jwteditor.model.jose.JWS;
import com.nimbusds.jose.util.Base64URL;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;

import static burp.api.montoya.core.Range.range;
import static burp.api.montoya.http.message.requests.HttpRequest.httpRequest;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.singletonList;

class JWSHeaderInsertionPoint implements AuditInsertionPoint {
    private final HttpRequest baseRequest;
    private final JWS jws;
    private final String headerParameterName;
    private final String encodedJWS;
    private final int startOffset;
    private final byte[] baseRequestPrefix;
    private final byte[] baseRequestPostfix;
    private final JSONObject headerJsonObject;

    JWSHeaderInsertionPoint(HttpRequest baseRequest, JWS jws, String headerParameterName, String encodedJWS) {
        this.baseRequest = baseRequest;
        this.jws = jws;
        this.headerParameterName = headerParameterName;
        this.encodedJWS = encodedJWS;

        startOffset = baseRequest.toString().indexOf(encodedJWS);
        int endOffset = startOffset + encodedJWS.length();

        ByteArray baseRequestBytes = baseRequest.toByteArray();
        baseRequestPrefix = startOffset == 0 ? new byte[0] : baseRequestBytes.subArray(0, startOffset).getBytes();
        baseRequestPostfix = endOffset == baseRequestBytes.length() ? new byte[0] : baseRequestBytes.subArray(endOffset, baseRequestBytes.length()).getBytes();

        try {
            headerJsonObject = new JSONObject(jws.getHeader());
        } catch (JSONException e) {
            throw new IllegalStateException("Could not parse JWS header!", e);
        }
    }

    @Override
    public String name() {
        return "JWS header '%s'".formatted(headerParameterName);
    }

    @Override
    public String baseValue() {
        return encodedJWS;
    }

    @Override
    public HttpRequest buildHttpRequestWithPayload(ByteArray payload) {
        byte[] updatedJWSBytes = buildWeaponizedJWS(payload);

        int l = baseRequestPrefix.length + updatedJWSBytes.length + baseRequestPostfix.length;
        byte[] modifiedRequest = new byte[l];
        System.arraycopy(baseRequestPrefix, 0, modifiedRequest, 0, baseRequestPrefix.length);
        System.arraycopy(updatedJWSBytes, 0, modifiedRequest, baseRequestPrefix.length, updatedJWSBytes.length);
        System.arraycopy(baseRequestPostfix, 0, modifiedRequest, baseRequestPrefix.length + updatedJWSBytes.length, baseRequestPostfix.length);

        return httpRequest(baseRequest.httpService(), ByteArray.byteArray(modifiedRequest));
    }

    @Override
    public List<Range> issueHighlights(ByteArray payload) {
        return singletonList(range(startOffset, startOffset + buildWeaponizedJWS(payload).length));
    }

    private byte[] buildWeaponizedJWS(ByteArray payload) {
        headerJsonObject.put(headerParameterName, payload.toString());
        Base64URL headerBase64 = Base64URL.encode(headerJsonObject.toString());

        return "%s.%s.%s".formatted(headerBase64, jws.getEncodedPayload(), jws.getEncodedSignature()).getBytes(UTF_8);
    }
}
