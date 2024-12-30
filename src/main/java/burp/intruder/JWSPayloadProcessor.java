/*
Author : Dolph Flynn

Copyright 2024 Dolph Flynn

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

package burp.intruder;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;
import burp.api.montoya.intruder.PayloadProcessor;
import burp.api.montoya.logging.Logging;
import com.blackberry.jwteditor.exceptions.SigningException;
import com.blackberry.jwteditor.model.jose.*;
import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.model.keys.KeysRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import org.json.JSONObject;

import java.util.Optional;

import static burp.intruder.FuzzLocation.PAYLOAD;
import static com.blackberry.jwteditor.model.jose.JOSEObjectFinder.parseJOSEObject;
import static com.nimbusds.jose.HeaderParameterNames.ALGORITHM;

public class JWSPayloadProcessor implements PayloadProcessor {
    private final Logging logging;
    private final IntruderConfig intruderConfig;
    private final KeysRepository keysRepository;

    public JWSPayloadProcessor(IntruderConfig intruderConfig, Logging logging, KeysRepository keysRepository) {
        this.logging = logging;
        this.intruderConfig = intruderConfig;
        this.keysRepository = keysRepository;
    }

    @Override
    public PayloadProcessingResult processPayload(PayloadData payloadData) {
        ByteArray baseValue = payloadData.insertionPoint().baseValue();
        Optional<JOSEObject> joseObject = parseJOSEObject(baseValue.toString());

        if (joseObject.isPresent() && (joseObject.get() instanceof JWS jws)) {
            boolean fuzzPayload = intruderConfig.fuzzLocation() == PAYLOAD;
            Header header = jws.header();
            JWSClaims jwsClaims = jws.claims();
            String targetData = fuzzPayload ? jwsClaims.decoded() : header.decoded();
            JSONObject targetJson = new JSONObject(targetData);

            if (targetJson.has(intruderConfig.fuzzParameter())) {
                targetJson.put(intruderConfig.fuzzParameter(), payloadData.currentPayload().toString());

                Base64URL updatedHeader = fuzzPayload ? header.encoded() : Base64URL.encode(targetJson.toString());

                Base64URL updatedPayload = fuzzPayload
                        ? Base64URL.encode(targetJson.toString())
                        : jwsClaims.encoded();

                JWS updatedJws = createJWS(updatedHeader, updatedPayload, jws.signature().encoded());
                baseValue = ByteArray.byteArray(updatedJws.serialize());
            }
        }

        return PayloadProcessingResult.usePayload(baseValue);
    }

    private Optional<Key> loadKey() {
        if (!intruderConfig.resign()) {
            return Optional.empty();
        }

        Key key = keysRepository.getKey(intruderConfig.signingKeyId());

        if (key == null) {
            logging.logToError("Key with ID " + intruderConfig.signingKeyId() + " not found.");
        }

        return Optional.ofNullable(key);
    }

    @Override
    public String displayName() {
        return "JWS payload processor";
    }

    // Creates a JWS object from the given attributes. Signs the JWS if possible (i.e., available key selected in Intruder settings)
    private JWS createJWS(Base64URL header, Base64URL payload, Base64URL originalSignature) {
        return loadKey()
                .flatMap(key -> {
                    try {
                        JWSAlgorithm algorithm = intruderConfig.signingAlgorithm();

                        String headerJson = header.decodeToString();
                        JSONObject headerJsonObject = new JSONObject(headerJson);

                        Object originalAlgorithm = headerJsonObject.get(ALGORITHM);
                        headerJsonObject.put(ALGORITHM, algorithm.getName());

                        // Only update when alg different to preserve key order
                        Base64URL updatedHeader = originalAlgorithm instanceof JWSAlgorithm alg && alg.equals(algorithm)
                                ? header
                                : Base64URL.encode(headerJsonObject.toString());

                        return Optional.of(JWSFactory.sign(key, algorithm, updatedHeader, payload));
                    } catch (SigningException ex) {
                        logging.logToError("Failed to sign JWS: " + ex);
                        return Optional.empty();
                    }
                })
                .orElseGet(
                        () -> JWSFactory.jwsFromParts(header, payload, originalSignature)
                );
    }
}
