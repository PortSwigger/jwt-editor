package com.blackberry.jwteditor.view.config;

import burp.intruder.FuzzLocation;
import burp.intruder.IntruderConfig;
import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.model.keys.KeysModel;
import com.blackberry.jwteditor.model.keys.KeysModelListener.SimpleKeysModelListener;
import com.nimbusds.jose.JWSAlgorithm;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.ArrayList;
import java.util.List;

import static java.util.Arrays.stream;

class IntruderConfigModel {
    static final String SIGNING_KEYS_UPDATED = "signingKeysUpdated";
    static final String SELECTED_KEY_UPDATED = "selectedKeyUpdated";
    static final String SIGNING_ALGORITHMS_UPDATED = "signingAlgorithmsUpdated";
    static final String SELECTED_ALGORITHM_UPDATED = "selectedAlgorithmUpdated";
    static final String RESIGN_UPDATED = "resignUpdated";

    private static final JWSAlgorithm[] NO_ALGORITHMS = new JWSAlgorithm[0];

    private final PropertyChangeSupport propertyChangeSupport;
    private final KeysModel keysModel;
    private final IntruderConfig intruderConfig;
    private final List<PropertyChangeListener> listeners;

    private String[] signingKeyIds;
    private JWSAlgorithm[] selectedKeySigningAlgorithms;

    IntruderConfigModel(KeysModel keysModel, IntruderConfig intruderConfig) {
        this.keysModel = keysModel;
        this.intruderConfig = intruderConfig;
        this.signingKeyIds = signingKeyIds();
        this.selectedKeySigningAlgorithms = signingAlgorithms();
        this.listeners = new ArrayList<>();
        this.propertyChangeSupport = new PropertyChangeSupport(this);

        keysModel.addKeyModelListener(new SimpleKeysModelListener(this::updateSigningKeyList));
    }

    String fuzzParameter() {
        return intruderConfig.fuzzParameter();
    }

    void setFuzzParameter(String fuzzParameter) {
        intruderConfig.setFuzzParameter(fuzzParameter);
    }

    FuzzLocation fuzzLocation() {
        return intruderConfig.fuzzLocation();
    }

    void setFuzzLocation(FuzzLocation fuzzLocation) {
        intruderConfig.setFuzzLocation(fuzzLocation);
    }

    FuzzLocation[] fuzzLocations() {
        return FuzzLocation.values();
    }

    boolean hasSigningKeys() {
        return !keysModel.getSigningKeys().isEmpty();
    }

    String[] signingKeyIds() {
        return keysModel.getSigningKeys().stream().map(Key::getID).toArray(String[]::new);
    }

    String signingKeyId() {
        String keyId = intruderConfig.signingKeyId();

        return keyId == null && hasSigningKeys() ? signingKeyIds()[0] : keyId;
    }

    public void setSigningKeyId(String signingKeyId) {
        String oldSigningKeyId = intruderConfig.signingKeyId();
        JWSAlgorithm[] oldAlgorithms = selectedKeySigningAlgorithms;
        intruderConfig.setSigningKeyId(signingKeyId);

        boolean selectedKeyUnchanged = (oldSigningKeyId == null && signingKeyId==null) || (oldSigningKeyId != null && oldSigningKeyId.equals(signingKeyId));

        if (!selectedKeyUnchanged) {
            selectedKeySigningAlgorithms = signingAlgorithms();
            propertyChangeSupport.firePropertyChange(SIGNING_ALGORITHMS_UPDATED, oldAlgorithms, selectedKeySigningAlgorithms);
        }
    }

    JWSAlgorithm[] signingAlgorithms() {
        String keyId = signingKeyId();

        if (keyId == null) {
            return NO_ALGORITHMS;
        }

        return keysModel.getSigningKeys().stream()
                .filter(k -> k.getID().equals(keyId))
                .findFirst()
                .orElseThrow()
                .getSigningAlgorithms();
    }

    JWSAlgorithm signingAlgorithm() {
        JWSAlgorithm signingAlgorithm = intruderConfig.signingAlgorithm();

        return signingAlgorithm == null && hasSigningKeys() ? signingAlgorithms()[0] : signingAlgorithm;
    }

    void setSigningAlgorithm(JWSAlgorithm signingAlgorithm) {
        intruderConfig.setSigningAlgorithm(signingAlgorithm);
    }

    boolean resign() {
        return intruderConfig.resign() && hasSigningKeys();
    }

    void setResign(boolean resign) {
        intruderConfig.setResign(resign);
    }

    void addPropertyChangeListener(PropertyChangeListener listener) {
        listeners.add(listener);
        propertyChangeSupport.addPropertyChangeListener(listener);
    }

    void clearListeners() {
        listeners.forEach(propertyChangeSupport::removePropertyChangeListener);
    }

    private void updateSigningKeyList() {
        String[] oldSigningKeyIds = signingKeyIds;
        JWSAlgorithm[] oldSigningAlgorithms = selectedKeySigningAlgorithms;
        JWSAlgorithm oldSigningAlgorithm = intruderConfig.signingAlgorithm();
        signingKeyIds = signingKeyIds();
        propertyChangeSupport.firePropertyChange(SIGNING_KEYS_UPDATED, oldSigningKeyIds, signingKeyIds);

        String selectedKeyId = intruderConfig.signingKeyId();
        boolean modelIsEmpty = signingKeyIds.length == 0;
        boolean modelWasEmpty = oldSigningKeyIds.length == 0 && signingKeyIds.length > 0;
        boolean selectedKeyDeleted = selectedKeyId != null && (signingKeyIds.length == 0 || stream(signingKeyIds).noneMatch(selectedKeyId::equals));
        boolean wasResigning = intruderConfig.resign();

        if (modelIsEmpty) {
            selectedKeySigningAlgorithms = NO_ALGORITHMS;
            propertyChangeSupport.firePropertyChange(SIGNING_ALGORITHMS_UPDATED, oldSigningAlgorithms, NO_ALGORITHMS);

            String oldSigningKeyId = intruderConfig.signingKeyId();
            intruderConfig.setSigningKeyId(null);
            propertyChangeSupport.firePropertyChange(SELECTED_KEY_UPDATED, oldSigningKeyId, null);

            intruderConfig.setSigningAlgorithm(null);
            propertyChangeSupport.firePropertyChange(SELECTED_ALGORITHM_UPDATED, oldSigningAlgorithm, null);

            intruderConfig.setResign(false);
            propertyChangeSupport.firePropertyChange(RESIGN_UPDATED, wasResigning, false);
        }
        else if (modelWasEmpty || selectedKeyDeleted) {
            String firstKeyId = signingKeyIds[0];
            intruderConfig.setSigningKeyId(firstKeyId);
            selectedKeySigningAlgorithms = signingAlgorithms();
            JWSAlgorithm firstSigningAlgorithm = selectedKeySigningAlgorithms[0];
            intruderConfig.setSigningAlgorithm(firstSigningAlgorithm);
            intruderConfig.setResign(false);

            propertyChangeSupport.firePropertyChange(SELECTED_KEY_UPDATED, null, firstKeyId);
            propertyChangeSupport.firePropertyChange(SIGNING_ALGORITHMS_UPDATED, oldSigningAlgorithms, selectedKeySigningAlgorithms);
            propertyChangeSupport.firePropertyChange(SELECTED_ALGORITHM_UPDATED, oldSigningAlgorithm, firstSigningAlgorithm);
            propertyChangeSupport.firePropertyChange(RESIGN_UPDATED, wasResigning, false);
        }
    }
}
