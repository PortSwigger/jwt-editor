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

package burp.config;

import burp.api.montoya.persistence.Preferences;
import burp.intruder.FuzzLocation;
import burp.intruder.IntruderConfig;
import burp.proxy.HighlightColor;
import burp.proxy.ProxyConfig;
import burp.scanner.ScannerConfig;
import com.nimbusds.jose.JWSAlgorithm;
import org.json.JSONException;
import org.json.JSONObject;

public class BurpConfigPersistence {
    static final String BURP_SETTINGS_NAME = "com.blackberry.jwteditor.settings";

    private static final String PROXY_LISTENER_ENABLED_KEY = "proxy_listener_enabled";
    private static final String PROXY_HISTORY_HIGHLIGHT_COLOR_KEY = "proxy_history_highlight_color";
    private static final String INTRUDER_FUZZ_PARAMETER_TYPE = "intruder_payload_processor_fuzz_location";
    private static final String INTRUDER_FUZZ_PARAMETER_NAME = "intruder_payload_processor_parameter_name";
    private static final String INTRUDER_FUZZ_RESIGNING = "intruder_payload_processor_resign";
    private static final String INTRUDER_FUZZ_SIGNING_KEY_ID = "intruder_payload_processor_signing_key_id";
    private static final String INTRUDER_FUZZ_SIGNING_ALGORITHM = "intruder_payload_processor_signing_algorithm";
    private static final String SCANNER_INSERTION_POINT_PROVIDER_ENABLED_KEY = "scanner_insertion_point_provider_enabled";
    private static final String SCANNER_INSERTION_PARAMETER_NAME = "scanner_insertion_point_provider_parameter_name";

    private final Preferences preferences;

    public BurpConfigPersistence(Preferences preferences) {
        this.preferences = preferences;
    }

    public BurpConfig loadOrCreateNew() {
        String json = preferences.getString(BURP_SETTINGS_NAME);

        if (json == null) {
            return new BurpConfig();
        }

        try {
            JSONObject parsedObject = new JSONObject(json);
            BurpConfig burpConfig = new BurpConfig();

            if (parsedObject.has(PROXY_LISTENER_ENABLED_KEY) && parsedObject.has(PROXY_HISTORY_HIGHLIGHT_COLOR_KEY)) {
                ProxyConfig proxyConfig = burpConfig.proxyConfig();

                proxyConfig.setHighlightJWT((Boolean) parsedObject.get(PROXY_LISTENER_ENABLED_KEY));

                String highlightColorName = (String) parsedObject.get(PROXY_HISTORY_HIGHLIGHT_COLOR_KEY);
                proxyConfig.setHighlightColor(HighlightColor.from(highlightColorName));
            }

            if (parsedObject.has(INTRUDER_FUZZ_PARAMETER_TYPE) && parsedObject.has(INTRUDER_FUZZ_PARAMETER_NAME)) {
                IntruderConfig intruderConfig = burpConfig.intruderConfig();

                intruderConfig.setFuzzParameter((String) parsedObject.get(INTRUDER_FUZZ_PARAMETER_NAME));

                String fuzzLocationName = (String) parsedObject.get(INTRUDER_FUZZ_PARAMETER_TYPE);
                intruderConfig.setFuzzLocation(FuzzLocation.from(fuzzLocationName));

                if (parsedObject.has(INTRUDER_FUZZ_SIGNING_KEY_ID) && parsedObject.get(INTRUDER_FUZZ_SIGNING_KEY_ID) instanceof String keyId) {
                    intruderConfig.setSigningKeyId(keyId);
                }

                if (parsedObject.has(INTRUDER_FUZZ_SIGNING_ALGORITHM) && parsedObject.get(INTRUDER_FUZZ_SIGNING_ALGORITHM) instanceof String algorithm) {
                    JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(algorithm);
                    intruderConfig.setSigningAlgorithm(jwsAlgorithm);
                }

                if (parsedObject.has(INTRUDER_FUZZ_RESIGNING) && parsedObject.get(INTRUDER_FUZZ_RESIGNING) instanceof Boolean resign) {
                    intruderConfig.setResign(resign);
                }
            }

            if (parsedObject.has(SCANNER_INSERTION_POINT_PROVIDER_ENABLED_KEY) && parsedObject.has(SCANNER_INSERTION_PARAMETER_NAME)) {
                ScannerConfig scannerConfig = burpConfig.scannerConfig();

                scannerConfig.setEnableHeaderJWSInsertionPointLocation((Boolean) parsedObject.get(SCANNER_INSERTION_POINT_PROVIDER_ENABLED_KEY));

                String insertionPointParameterName = (String) parsedObject.get(SCANNER_INSERTION_PARAMETER_NAME);
                scannerConfig.setInsertionPointLocationParameterName(insertionPointParameterName);
            }

            return burpConfig;
        } catch (ClassCastException | JSONException ignored) {
            return new BurpConfig();
        }
    }

    public void save(BurpConfig model) {
        // Serialise the Burp config and save
        JSONObject burpConfigJson = new JSONObject();

        burpConfigJson.put(PROXY_LISTENER_ENABLED_KEY, model.proxyConfig().highlightJWT());
        burpConfigJson.put(PROXY_HISTORY_HIGHLIGHT_COLOR_KEY, model.proxyConfig().highlightColor().burpColor);
        burpConfigJson.put(INTRUDER_FUZZ_PARAMETER_NAME, model.intruderConfig().fuzzParameter());
        burpConfigJson.put(INTRUDER_FUZZ_PARAMETER_TYPE, model.intruderConfig().fuzzLocation());
        burpConfigJson.put(INTRUDER_FUZZ_RESIGNING, model.intruderConfig().resign());
        burpConfigJson.put(INTRUDER_FUZZ_SIGNING_KEY_ID, model.intruderConfig().signingKeyId());

        JWSAlgorithm signingAlgorithm = model.intruderConfig().signingAlgorithm();
        String signingAlgorithmName = signingAlgorithm == null ? null : signingAlgorithm.getName();
        burpConfigJson.put(INTRUDER_FUZZ_SIGNING_ALGORITHM, signingAlgorithmName);

        burpConfigJson.put(SCANNER_INSERTION_POINT_PROVIDER_ENABLED_KEY, model.scannerConfig().enableHeaderJWSInsertionPointLocation());
        burpConfigJson.put(SCANNER_INSERTION_PARAMETER_NAME, model.scannerConfig().insertionPointLocationParameterName());

        preferences.setString(BURP_SETTINGS_NAME, burpConfigJson.toString());
    }
}
