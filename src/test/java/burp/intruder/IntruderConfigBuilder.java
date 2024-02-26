package burp.intruder;

import com.nimbusds.jose.JWSAlgorithm;

class IntruderConfigBuilder {
    private final IntruderConfig config;

    private IntruderConfigBuilder() {
        this.config = new IntruderConfig();
    }

    IntruderConfigBuilder withFuzzLocation(FuzzLocation fuzzLocation) {
        config.setFuzzLocation(fuzzLocation);
        return this;
    }

    IntruderConfigBuilder withFuzzParameter(String parameterName) {
        config.setFuzzParameter(parameterName);
        return this;
    }

    IntruderConfigBuilder withSigningKeyId(String signingId) {
        config.setSigningKeyId(signingId);
        return this;
    }

    IntruderConfigBuilder withSigningAlgorithm(JWSAlgorithm algorithm) {
        config.setSigningAlgorithm(algorithm);
        return this;
    }

    IntruderConfigBuilder withResigning(boolean resign) {
        config.setResign(resign);
        return this;
    }

    IntruderConfig build() {
        return config;
    }

    static IntruderConfigBuilder intruderConfig() {
        return new IntruderConfigBuilder();
    }
}
