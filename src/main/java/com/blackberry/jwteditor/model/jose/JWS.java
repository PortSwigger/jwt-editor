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

package com.blackberry.jwteditor.model.jose;

import com.blackberry.jwteditor.exceptions.VerificationException;
import com.blackberry.jwteditor.model.keys.Key;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.util.Base64URL;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static com.blackberry.jwteditor.model.jose.JWSVerifierFactory.verifierFor;

/**
 * Class representing a JWS
 */
public class JWS extends JOSEObject {
    private final JWSClaims claims;
    private final Signature signature;

    /**
     * Construct a JWS from encoded components
     * @param header the encoded header
     * @param payload the encoded payload
     * @param signature the encoded signature
     */
    JWS(Base64URL header, Base64URL payload, Base64URL signature) {
        super(header);
        this.claims = new JWSClaims(payload);
        this.signature = new Signature(signature);
    }

    public JWSClaims claims() {
        return claims;
    }

    public Signature signature() {
        return signature;
    }

    /**
     * Serialize the JWS to compact form
     *
     * @return the JWS in compact form
     */
    @Override
    public String serialize() {
        return "%s.%s.%s".formatted(header.toString(), claims.toString(), signature.toString());
    }

    @Override
    public List<Information> information() {
        return claims.timeClaims().stream()
                .map(Information::from)
                .toList();
    }

    /**
     * Verify JWS with a JWK and an algorithm
     *
     * @param key              JWK for verification
     * @param verificationInfo JWSHeader containing verification algorithm
     * @return result of signature verification
     * @throws VerificationException if verification process fails
     */
    public boolean verify(Key key, JWSHeader verificationInfo) throws VerificationException {
        JWSVerifier verifier = verifierFor(key, verificationInfo.getAlgorithm());

        // Build the signing input
        // JWS signature input is the ASCII bytes of the base64 encoded header and payload concatenated with a '.'
        byte[] headerBytes = header.toString().getBytes(StandardCharsets.US_ASCII);
        byte[] payloadBytes = claims.encoded().toString().getBytes(StandardCharsets.US_ASCII);
        byte[] signingInput = new byte[headerBytes.length + 1 + payloadBytes.length];
        System.arraycopy(headerBytes, 0, signingInput, 0, headerBytes.length);
        signingInput[headerBytes.length] = '.';
        System.arraycopy(payloadBytes, 0, signingInput, headerBytes.length + 1, payloadBytes.length);

        // Verify the payload with the key and the algorithm provided
        try {
            return verifier.verify(verificationInfo, signingInput, signature.encoded());
        } catch (JOSEException e) {
            throw new VerificationException(e.getMessage());
        }
    }
}
