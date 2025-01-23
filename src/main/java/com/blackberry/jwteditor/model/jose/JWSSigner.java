/*
Author : Dolph Flynn

Copyright 2022 Dolph Flynn

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

import com.blackberry.jwteditor.exceptions.SigningException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;

import java.nio.charset.StandardCharsets;

class JWSSigner {
    private final com.nimbusds.jose.JWSSigner signer;

    JWSSigner(com.nimbusds.jose.JWSSigner signer) {
        this.signer = signer;
    }

    public JWS sign(Base64URL header, Base64URL payload, JWSHeader signingInfo) throws SigningException {
        // Build the signing input
        // JWS signature input is the ASCII bytes of the base64 encoded header and payload concatenated with a '.'
        byte[] headerBytes = header.toString().getBytes(StandardCharsets.US_ASCII);
        byte[] payloadBytes = payload.toString().getBytes(StandardCharsets.US_ASCII);
        byte[] signingInput = new byte[headerBytes.length + 1 + payloadBytes.length];
        System.arraycopy(headerBytes, 0, signingInput, 0, headerBytes.length);
        signingInput[headerBytes.length] = '.';
        System.arraycopy(payloadBytes, 0, signingInput, headerBytes.length + 1, payloadBytes.length);

        // Sign the payload with the key and the algorithm provided
        Base64URL encodedSignature;
        try {
            encodedSignature = signer.sign(signingInfo, signingInput);
        } catch (JOSEException e) {
            throw new SigningException(e.getMessage());
        }

        // Return a new JWS consisting of the three components
        return new JWS(header, payload, encodedSignature);
    }
}
