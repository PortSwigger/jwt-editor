package com.blackberry.jwteditor.view.config;

import burp.intruder.FuzzLocation;
import burp.intruder.IntruderConfig;
import com.blackberry.jwteditor.model.keys.KeysModel;
import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.beans.PropertyChangeEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static burp.intruder.FuzzLocation.HEADER;
import static com.blackberry.jwteditor.KeyLoader.*;
import static com.blackberry.jwteditor.view.config.IntruderConfigModel.*;
import static com.nimbusds.jose.JWSAlgorithm.*;
import static data.PemData.*;
import static java.util.Arrays.asList;
import static java.util.Arrays.stream;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class IntruderConfigModelTest {
    private static final String KEY_ID = "id";

    private final KeysModel keysModel = new KeysModel();
    private final IntruderConfig wrappedConfig = new IntruderConfig();
    private final IntruderConfigModel model = new IntruderConfigModel(keysModel, wrappedConfig);

    @AfterEach
    void cleanUp() {
        model.clearListeners();
        stream(model.signingKeyIds()).forEach(keysModel::deleteKey);
    }

    @Test
    void whenSetFuzzParameter_thenValueSetOnModelAndWrappedConfig() {
        String parameter = "kid";
        model.setFuzzParameter(parameter);

        assertThat(model.fuzzParameter()).isEqualTo(parameter);
        assertThat(wrappedConfig.fuzzParameter()).isEqualTo(parameter);
    }

    @Test
    void whenGetFuzzParameter_thenValueRetrievedFromWrappedConfig() {
        String parameter = "kid";
        wrappedConfig.setFuzzParameter(parameter);

        assertThat(model.fuzzParameter()).isEqualTo(parameter);
    }

    @Test
    void whenSetFuzzLocation_thenValueSetOnModelAndWrappedConfig() {
        FuzzLocation location = HEADER;
        model.setFuzzLocation(location);

        assertThat(model.fuzzLocation()).isEqualTo(location);
        assertThat(wrappedConfig.fuzzLocation()).isEqualTo(location);
    }

    @Test
    void whenGetFuzzLocation_thenValueRetrievedFromWrappedConfig() {
        FuzzLocation location = HEADER;
        wrappedConfig.setFuzzLocation(location);

        assertThat(model.fuzzLocation()).isEqualTo(location);
    }

    @Test
    void whenGetFuzzLocations_thenAllFuzzLocationValuesReturned() {
        assertThat(model.fuzzLocations()).containsExactly(FuzzLocation.values());
    }

    @Test
    void whenEmptyKeysModel_thenHasSigningKeyIsFalse() {
        assertThat(model.hasSigningKeys()).isFalse();
    }

    @Test
    void whenEmptyKeysModel_thenNoSigningKeyIds() {
        assertThat(model.signingKeyIds()).isEmpty();
    }

    @Test
    void whenEmptyKeysModel_thenSelectedSigningKeyIdIsNull() {
        assertThat(model.signingKeyId()).isNull();
    }

    @Test
    void whenEmptyKeysModel_thenNoSigningAlgorithms() {
        assertThat(model.signingAlgorithms()).isEmpty();
    }

    @Test
    void whenEmptyKeysModel_thenSelectedSigningAlgorithmsIsNull() {
        assertThat(model.signingAlgorithm()).isNull();
    }

    @Test
    void whenEmptyKeysModel_thenResignIsFalse() {
        wrappedConfig.setResign(true);

        assertThat(model.resign()).isFalse();
    }

    @Test
    void whenKeysModelNotEmptyButHasNoSigningKeys_thenHasSigningKeysIsFalse() {
        keysModel.addKey(loadOKPKey(X25519Public, "kid"));

        assertThat(model.hasSigningKeys()).isFalse();
    }

    @Test
    void whenKeysModelHasSigningKeys_thenHasSigningKeysIsTrue() {
        keysModel.addKey(loadRSAKey(RSA1024Private, "kid"));

        assertThat(model.hasSigningKeys()).isTrue();
    }

    @Test
    void whenKeysModelNotEmptyButHasNoSigningKeys_thenSigningKeyIdsEmpty() {
        keysModel.addKey(loadOKPKey(X25519Public, "kid"));

        assertThat(model.signingKeyIds()).isEmpty();
    }

    @Test
    void whenKeysModelHasSigningKeys_thenSigningKeyIdsNotEmpty() {
        keysModel.addKey(loadRSAKey(RSA1024Private, "kid1"));
        keysModel.addKey(loadECKey(PRIME256v1PrivateSEC1, "kid2"));

        assertThat(model.signingKeyIds()).containsExactly("kid1", "kid2");
    }

    @Test
    void whenKeysModelHasSigningAndNonSigningKeys_thenSigningKeyIdsContainsOnlySigningKeyIds() {
        keysModel.addKey(loadRSAKey(RSA1024Private, "kid1"));
        keysModel.addKey(loadOKPKey(X25519Public, "kid2"));
        keysModel.addKey(loadECKey(PRIME256v1PrivateSEC1, "kid3"));

        assertThat(model.signingKeyIds()).containsExactly("kid1", "kid3");
    }

    @Test
    void givenKeysModelHasSigningKey_whenSetSigningKeyId_thenSigningKeyAndSigningAlgorithmsUpdated() {
        String keyId = "kid1";
        keysModel.addKey(loadRSAKey(RSA1024Private, keyId));

        model.setSigningKeyId(keyId);

        assertThat(model.signingKeyId()).isEqualTo(keyId);
        assertThat(wrappedConfig.signingKeyId()).isEqualTo(keyId);
        assertThat(model.signingAlgorithms()).containsExactly(RS256, RS384, RS512, PS256, PS384);
    }

    @Test
    void givenKeysModelHasSigningKey_whenSetInvalidSigningKeyId_thenExceptionThrown() {
        keysModel.addKey(loadRSAKey(RSA1024Private, "kid1"));

        assertThrows(NoSuchElementException.class, () -> model.setSigningKeyId("invalid"));
    }

    @Test
    void givenKeysModelHasSigningKey_whenSetSigningKeyId_thenSigningAlgorithmsUpdatedEventPublished() {
        List<JWSAlgorithm> publishedAlgorithms = new ArrayList<>();
        model.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals(SIGNING_ALGORITHMS_UPDATED) && evt.getNewValue() instanceof JWSAlgorithm[] algorithms) {
                publishedAlgorithms.addAll(asList(algorithms));
            }
        });

        String keyId = "kid1";
        keysModel.addKey(loadRSAKey(RSA1024Private, keyId));

        model.setSigningKeyId(keyId);

        assertThat(publishedAlgorithms).containsExactly(RS256, RS384, RS512, PS256, PS384);
    }

    @Test
    void givenKeysModelHasSigningKey_whenSetAlgorithm_thenAlgorithmStored() {
        String keyId = "kid1";
        keysModel.addKey(loadRSAKey(RSA1024Private, keyId));

        model.setSigningAlgorithm(PS256);

        assertThat(model.signingAlgorithm()).isEqualTo(PS256);
        assertThat(wrappedConfig.signingAlgorithm()).isEqualTo(PS256);
    }

    @Test
    void givenNoSelectedKeyIdOrAlgorithm_whenSetResign_thenResignFalse() {
        model.setResign(true);

        assertThat(model.resign()).isFalse();
    }

    @Test
    void givenSelectedAlgorithmButNoKeyId_whenSetResign_thenResignFalse() {
        model.setSigningAlgorithm(EdDSA);

        model.setResign(true);

        assertThat(model.resign()).isFalse();
    }

    @Test
    void givenSelectedKeyIdAndAlgorithm_whenSetResign_thenResignFalse() {
        String keyId = "kid";
        keysModel.addKey(loadRSAKey(RSA1024Private, keyId));
        model.setSigningKeyId(keyId);
        model.setSigningAlgorithm(RS256);

        model.setResign(true);

        assertThat(model.resign()).isTrue();
    }

    @Test
    void whenKeyAddedToModel_thenSigningKeysUpdatedEventFired() {
        List<String> oldIds = new ArrayList<>();
        List<String> newIds = new ArrayList<>();
        model.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals(SIGNING_KEYS_UPDATED)) {
                oldIds.addAll(asList((String[]) evt.getOldValue()));
                newIds.addAll(asList((String[]) evt.getNewValue()));
            }
        });

        keysModel.addKey(loadRSAKey(RSA1024Private, KEY_ID));

        assertThat(oldIds).isEmpty();
        assertThat(newIds).containsExactly(KEY_ID);
    }

    @Test
    void whenKeyDeletedFromModel_thenSigningKeysUpdatedEventFired() {
        List<String> oldIds = new ArrayList<>();
        List<String> newIds = new ArrayList<>();
        keysModel.addKey(loadRSAKey(RSA1024Private, KEY_ID));
        model.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals(SIGNING_KEYS_UPDATED)) {
                oldIds.addAll(asList((String[]) evt.getOldValue()));
                newIds.addAll(asList((String[]) evt.getNewValue()));
            }
        });

        keysModel.deleteKey(KEY_ID);

        assertThat(oldIds).containsExactly(KEY_ID);
        assertThat(newIds).isEmpty();
    }

    @Test
    void givenSelectedKey_whenSelectedKeyDeletedFromModel_thenSelectedKeyUpdatedFired() {
        keysModel.addKey(loadRSAKey(RSA1024Private, KEY_ID));
        model.setSigningKeyId(KEY_ID);
        AtomicReference<PropertyChangeEvent> event = new AtomicReference<>();
        model.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals(SELECTED_KEY_UPDATED)) {
                event.set(evt);
            }
        });

        keysModel.deleteKey(KEY_ID);

        assertThat(event.get().getOldValue()).isEqualTo(KEY_ID);
        assertThat(event.get().getNewValue()).isNull();
    }

    @Test
    void givenSelectedKey_whenSelectedKeyDeletedFromModel_thenSigningAlgorithmsEventUpdatedFired() {
        List<JWSAlgorithm> oldAlgorithms = new ArrayList<>();
        List<JWSAlgorithm> newAlgorithms = new ArrayList<>();
        keysModel.addKey(loadRSAKey(RSA1024Private, KEY_ID));
        model.setSigningKeyId(KEY_ID);
        model.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals(SIGNING_ALGORITHMS_UPDATED)) {
                oldAlgorithms.addAll(asList((JWSAlgorithm[]) evt.getOldValue()));
                newAlgorithms.addAll(asList((JWSAlgorithm[]) evt.getNewValue()));
            }
        });

        keysModel.deleteKey(KEY_ID);

        assertThat(oldAlgorithms).containsExactly(RS256, RS384, RS512, PS256, PS384);
        assertThat(newAlgorithms).isEmpty();
    }

    @Test
    void givenSelectedAlgorithm_whenSelectedKeyDeletedFromModel_thenSelectedAlgorithmUpdatedFired() {
        keysModel.addKey(loadRSAKey(RSA1024Private, KEY_ID));
        model.setSigningKeyId(KEY_ID);
        model.setSigningAlgorithm(RS256);
        AtomicReference<PropertyChangeEvent> event = new AtomicReference<>();
        model.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals(SELECTED_ALGORITHM_UPDATED)) {
                event.set(evt);
            }
        });

        keysModel.deleteKey(KEY_ID);

        assertThat(event.get().getOldValue()).isEqualTo(RS256);
        assertThat(event.get().getNewValue()).isNull();
    }

    @Test
    void givenSelectedAlgorithm_whenResigningAndSelectedKeyDeleted_thenResignDisabled() {
        AtomicBoolean resign = new AtomicBoolean(true);
        model.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals(RESIGN_UPDATED) && evt.getNewValue() instanceof Boolean selected) {
                resign.set(selected);
            }
        });
        keysModel.addKey(loadRSAKey(RSA1024Private, KEY_ID));
        model.setResign(true);

        keysModel.deleteKey(KEY_ID);

        assertThat(model.resign()).isFalse();
        assertThat(resign).isFalse();
    }

    @Test
    void givenEmptyModel_whenKeyLoaded_thenKeyAndFirstAlgorithmSelected() {
        keysModel.addKey(loadRSAKey(RSA1024Private, KEY_ID));

        assertThat(model.signingKeyId()).isEqualTo(KEY_ID);
        assertThat(wrappedConfig.signingKeyId()).isEqualTo(KEY_ID);
        assertThat(model.signingAlgorithm()).isEqualTo(RS256);
        assertThat(wrappedConfig.signingAlgorithm()).isEqualTo(RS256);
        assertThat(model.signingAlgorithms()).containsExactly(RS256, RS384, RS512, PS256, PS384);
    }

    @Test
    void givenEmptyModel_whenKeyLoaded_thenSigningKeysUpdatedEventFired() {
        List<String> oldIds = new ArrayList<>();
        List<String> newIds = new ArrayList<>();
        model.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals(SIGNING_KEYS_UPDATED)) {
                oldIds.addAll(asList((String[]) evt.getOldValue()));
                newIds.addAll(asList((String[]) evt.getNewValue()));
            }
        });

        keysModel.addKey(loadRSAKey(RSA1024Private, KEY_ID));

        assertThat(oldIds).isEmpty();
        assertThat(newIds).containsExactly(KEY_ID);
    }

    @Test
    void givenEmptyModel_whenKeyLoaded_thenSelectedKeyUpdatedEventFired() {
        AtomicReference<String> oldKeyId = new AtomicReference<>();
        AtomicReference<String> newKeyId = new AtomicReference<>();
        model.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals(SELECTED_KEY_UPDATED)) {
                oldKeyId.set((String) evt.getOldValue());
                newKeyId.set((String) evt.getNewValue());
            }
        });

        keysModel.addKey(loadRSAKey(RSA1024Private, KEY_ID));

        assertThat(oldKeyId.get()).isNull();
        assertThat(newKeyId.get()).isEqualTo(KEY_ID);
    }

    @Test
    void givenEmptyModel_whenKeyLoaded_thenSigningAlgorithmsUpdatedEventFired() {
        List<JWSAlgorithm> oldAlgorithms = new ArrayList<>();
        List<JWSAlgorithm> newAlgorithms = new ArrayList<>();
        model.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals(SIGNING_ALGORITHMS_UPDATED)) {
                oldAlgorithms.addAll(asList((JWSAlgorithm[]) evt.getOldValue()));
                newAlgorithms.addAll(asList((JWSAlgorithm[]) evt.getNewValue()));
            }
        });

        keysModel.addKey(loadRSAKey(RSA1024Private, KEY_ID));

        assertThat(oldAlgorithms).isEmpty();
        assertThat(newAlgorithms).containsExactly(RS256, RS384, RS512, PS256, PS384);
    }

    @Test
    void givenEmptyModel_whenKeyLoaded_thenSelectedAlgorithmUpdatedEventFired() {
        AtomicReference<JWSAlgorithm> oldSigningAlgorithm = new AtomicReference<>();
        AtomicReference<JWSAlgorithm> newSigningAlgorithm = new AtomicReference<>();
        model.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals(SELECTED_ALGORITHM_UPDATED)) {
                oldSigningAlgorithm.set((JWSAlgorithm) evt.getOldValue());
                newSigningAlgorithm.set((JWSAlgorithm) evt.getNewValue());
            }
        });

        keysModel.addKey(loadRSAKey(RSA1024Private, KEY_ID));

        assertThat(oldSigningAlgorithm.get()).isNull();
        assertThat(newSigningAlgorithm.get()).isEqualTo(RS256);
    }

    @Test
    void givenTwoKeysInModel_whenSelectedKeyDeleted_thenRemainingKeyAndFirstAlgorithmSelected() {
        String kid = "kid2";
        keysModel.addKey(loadRSAKey(RSA1024Private, kid));
        keysModel.addKey(loadOKPKey(ED25519Private, KEY_ID));

        keysModel.deleteKey(kid);

        assertThat(model.signingKeyId()).isEqualTo(KEY_ID);
        assertThat(wrappedConfig.signingKeyId()).isEqualTo(KEY_ID);
        assertThat(model.signingAlgorithm()).isEqualTo(EdDSA);
        assertThat(wrappedConfig.signingAlgorithm()).isEqualTo(EdDSA);
        assertThat(model.signingAlgorithms()).containsExactly(EdDSA);
    }

    @Test
    void givenTwoKeysInModel_whenResigningAndSelectedKeyDeleted_thenResignDisabled() {
        AtomicBoolean resign = new AtomicBoolean(true);
        model.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals(RESIGN_UPDATED) && evt.getNewValue() instanceof Boolean selected) {
                resign.set(selected);
            }
        });

        String kid = "kid2";
        keysModel.addKey(loadRSAKey(RSA1024Private, kid));
        keysModel.addKey(loadOKPKey(ED25519Private, KEY_ID));
        model.setResign(true);

        keysModel.deleteKey(kid);

        assertThat(model.resign()).isFalse();
        assertThat(resign).isFalse();
    }

    @Test
    void givenMultipleKeysInModel_whenSelectedKeyDeleted_thenFirstKeyAndAlgorithmSelected() {
        String kid = "kid2";
        keysModel.addKey(loadRSAKey(RSA1024Private, kid));
        keysModel.addKey(loadOKPKey(ED25519Private, KEY_ID));
        keysModel.addKey(loadOKPKey(X448Private, "kid3"));

        keysModel.deleteKey(kid);

        assertThat(model.signingKeyId()).isEqualTo(KEY_ID);
        assertThat(wrappedConfig.signingKeyId()).isEqualTo(KEY_ID);
        assertThat(model.signingAlgorithm()).isEqualTo(EdDSA);
        assertThat(wrappedConfig.signingAlgorithm()).isEqualTo(EdDSA);
        assertThat(model.signingAlgorithms()).containsExactly(EdDSA);
    }

    @Test
    void givenMultipleKeysInModel_whenResigningAndSelectedKeyDeleted_thenResignDisabled() {
        AtomicBoolean resign = new AtomicBoolean(true);
        model.addPropertyChangeListener(evt -> {
            if (evt.getPropertyName().equals(RESIGN_UPDATED) && evt.getNewValue() instanceof Boolean selected) {
                resign.set(selected);
            }
        });

        String kid = "kid2";
        keysModel.addKey(loadRSAKey(RSA1024Private, kid));
        keysModel.addKey(loadOKPKey(ED25519Private, KEY_ID));
        keysModel.addKey(loadOKPKey(X448Private, "kid3"));
        model.setResign(true);

        keysModel.deleteKey(kid);

        assertThat(model.resign()).isFalse();
        assertThat(resign).isFalse();
    }
}