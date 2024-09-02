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

package com.blackberry.jwteditor.presenter;

import burp.api.montoya.collaborator.CollaboratorPayloadGenerator;
import com.blackberry.jwteditor.model.jose.JOSEObject;
import com.blackberry.jwteditor.model.jose.JWE;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.jose.MutableJOSEObject;
import com.blackberry.jwteditor.model.keys.Key;
import com.blackberry.jwteditor.model.keys.KeyRing;
import com.blackberry.jwteditor.utils.Utils;
import com.blackberry.jwteditor.view.dialog.MessageDialogFactory;
import com.blackberry.jwteditor.view.dialog.operations.*;
import com.blackberry.jwteditor.view.editor.EditorMode;
import com.blackberry.jwteditor.view.editor.EditorView;
import com.blackberry.jwteditor.view.utils.ErrorLoggingActionListenerFactory;
import com.nimbusds.jose.util.Base64URL;
import org.json.JSONException;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static com.blackberry.jwteditor.model.jose.JOSEObjectFinder.containsJOSEObjects;
import static com.blackberry.jwteditor.model.jose.JWEFactory.jweFromParts;
import static com.blackberry.jwteditor.model.jose.JWSFactory.jwsFromParts;
import static com.blackberry.jwteditor.utils.Base64URLUtils.base64UrlEncodeJson;
import static com.blackberry.jwteditor.utils.JSONUtils.isJsonCompact;
import static com.blackberry.jwteditor.utils.JSONUtils.prettyPrintJSON;

/**
 * Presenter class for the Editor tab
 */
public class EditorPresenter extends Presenter {

    private final PresenterStore presenters;
    private final EditorView view;
    private final CollaboratorPayloadGenerator collaboratorPayloadGenerator;
    private final ErrorLoggingActionListenerFactory actionListenerFactory;
    private final MessageDialogFactory messageDialogFactory;
    private final EditorModel model;

    private boolean selectionChanging;

    public EditorPresenter(
            EditorView view,
            CollaboratorPayloadGenerator collaboratorPayloadGenerator,
            ErrorLoggingActionListenerFactory actionListenerFactory,
            PresenterStore presenters) {
        this.view = view;
        this.collaboratorPayloadGenerator = collaboratorPayloadGenerator;
        this.actionListenerFactory = actionListenerFactory;
        this.presenters = presenters;
        this.model = new EditorModel();
        this.messageDialogFactory = new MessageDialogFactory(view.uiComponent());

        presenters.register(this);
    }

    /**
     * Determine if the tab should be enabled based on whether a block of text contains JWE/JWSs
     *
     * @param content text that may contain a serialized JWE/JWS
     * @return true if the content contains a JWE/JWS that can be edited
     */
    public boolean isEnabled(String content) {
        return containsJOSEObjects(content);
    }

    /**
     * Set the content of the editor tab by extracting and parsing JWE/JWSs from a block of text
     *
     * @param content text that may contain a serialized JWE/JWS
     */
    public void setMessage(String content) {
        model.setMessage(content);
        view.setJOSEObjects(model.getJOSEObjectStrings());
    }

    /**
     * Display a JWS in the editor
     *
     * @param jws the JWS to display
     */
    private void setJWS(JWS jws) {
        // Check if the header and payload survives compaction without changes (i.e. it was compact when deserialized)
        // If contain whitespace, don't try to pretty print, as the re-compacted version won't match the original

        String header = jws.getHeader();
        boolean isHeaderJsonCompact = isJsonCompact(header);
        String jwsHeader = isHeaderJsonCompact ? prettyPrintJSON(header) : header;

        view.setJWSHeader(jwsHeader);
        view.setJWSHeaderCompact(isHeaderJsonCompact);

        String payload = jws.getPayload();
        boolean isPayloadJsonCompact = isJsonCompact(payload);
        String jwsPayload = isPayloadJsonCompact ? prettyPrintJSON(payload) : payload;

        view.setJWSPayloadCompact(isPayloadJsonCompact);
        view.setPayload(jwsPayload);

        view.setSignature(jws.getSignature());
    }

    /**
     * Convert the text/hex entry fields to a JWS
     *
     * @return the JWS built from the editor entry fields
     */
    private JWS getJWS() {
        // Get the header and payload text entry as base64. Compact the JSON if corresponding compact checkbox is ticked
        // Return the entry encoded as-is if this fails, or the corresponding compact checkbox is unticked

        Base64URL header = base64UrlEncodeJson(view.getJWSHeader(), view.getJWSHeaderCompact());
        Base64URL payload = base64UrlEncodeJson(view.getPayload(), view.getJWSPayloadCompact());

        return jwsFromParts(header, payload, Base64URL.encode(view.getSignature()));
    }

    /**
     * Display a JWE in the editor
     *
     * @param jwe the JWE to display
     */
    private void setJWE(JWE jwe) {
        // Check if the header survives compaction without changes (i.e. it was compact when deserialized)
        String header = jwe.getHeader();

        boolean isHeaderJsonCompact = isJsonCompact(header);
        String jweHeader = isHeaderJsonCompact ? prettyPrintJSON(header) : header;

        view.setJWEHeader(jweHeader);
        view.setJWEHeaderCompact(isHeaderJsonCompact);

        // Set the other JWE fields - these are all byte arrays
        view.setEncryptedKey(jwe.getEncryptedKey());
        view.setCiphertext(jwe.getCiphertext());
        view.setIV(jwe.getIV());
        view.setTag(jwe.getTag());
    }

    /**
     * Convert the text/hex entry fields to a JWE
     *
     * @return the JWE built from the editor entry fields
     */
    private JWE getJWE() {
        // Get the header text entry as base64. Compact the JSON if the compact checkbox is ticked
        // Return the entry encoded as-is if this fails, or the compact checkbox is unticked
        Base64URL header = base64UrlEncodeJson(view.getJWEHeader(), view.getJWEHeaderCompact());

        Base64URL encryptedKey = Base64URL.encode(view.getEncryptedKey());
        Base64URL iv = Base64URL.encode(view.getIV());
        Base64URL ciphertext = Base64URL.encode(view.getCiphertext());
        Base64URL tag = Base64URL.encode(view.getTag());

        return jweFromParts(header, encryptedKey, iv, ciphertext, tag);
    }

    /**
     * Handle clicks events from the Embedded JWK Attack button
     */
    public void onAttackEmbedJWKClicked() {
        signingDialog(SignDialog.Mode.EMBED_JWK);
    }

    /**
     * Handle click events from the HMAC Key Confusion button
     */
    public void onAttackKeyConfusionClicked() {
        KeysPresenter keysPresenter = (KeysPresenter) presenters.get(KeysPresenter.class);

        List<Key> attackKeys = new ArrayList<>();

        // Get a list of verification capable public keys
        List<Key> verificationKeys = keysPresenter.getVerificationKeys();
        for (Key signingKey : verificationKeys) {
            if (signingKey.isPublic() && signingKey.hasPEM()) {
                attackKeys.add(signingKey);
            }
        }

        if (attackKeys.isEmpty()) {
            messageDialogFactory.showWarningDialog("error_title_no_signing_keys", "error_no_signing_keys");
            return;
        }

        // Create the key confusion attack dialog with the JWS currently in the editor fields
        KeyConfusionAttackDialog keyConfusionAttackDialog = new KeyConfusionAttackDialog(
                view.window(),
                actionListenerFactory,
                verificationKeys,
                getJWS()
        );
        keyConfusionAttackDialog.display();

        // Set the result as the JWS in the editor if the attack succeeds
        JWS signedJWS = keyConfusionAttackDialog.getJWS();
        if (signedJWS != null) {
            setJWS(signedJWS);
        }
    }

    /**
     * Handle clicks events from the none Signing algorithm button
     */
    public void onAttackSignNoneClicked() {
        // Get the JWS from the editor, strip the signature and set the editor to the new JWS
        NoneDialog noneDialog = new NoneDialog(view.window(), getJWS());
        noneDialog.display();

        JWS unsignedJWS = noneDialog.getJWS();

        if (unsignedJWS != null) {
            setJWS(unsignedJWS);
        }
    }

    public void onAttackSignEmptyKeyClicked() {
        EmptyKeySigningDialog signingDialog = new EmptyKeySigningDialog(view.window(), actionListenerFactory, getJWS());
        signingDialog.display();

        JWS signedJWS = signingDialog.getJWS();

        if (signedJWS != null) {
            setJWS(signedJWS);
        }
    }

    public void onAttackPsychicSignatureClicked() {
        PsychicSignatureDialog signingDialog = new PsychicSignatureDialog(view.window(), getJWS());
        signingDialog.display();

        JWS signedJWS = signingDialog.getJWS();

        if (signedJWS != null) {
            setJWS(signedJWS);
        }
    }

    public void onAttackEmbedCollaboratorPayloadClicked() {
        EmbedCollaboratorPayloadDialog collaboratorPayloadDialog = new EmbedCollaboratorPayloadDialog(
                view.window(),
                getJWS(),
                collaboratorPayloadGenerator
        );

        collaboratorPayloadDialog.display();

        JWS updatedJWS = collaboratorPayloadDialog.getJWS();

        if (updatedJWS != null) {
            setJWS(updatedJWS);
        }
    }

    /**
     * Handle click events from the Sign button
     */
    public void onSignClicked() {
        signingDialog(SignDialog.Mode.NORMAL);
    }

    /**
     * Create a signing dialog based on the provided mode
     *
     * @param mode mode of the signing dialog to display
     */
    private void signingDialog(SignDialog.Mode mode) {
        KeysPresenter keysPresenter = (KeysPresenter) presenters.get(KeysPresenter.class);

        // Check there are signing keys in the keystore
        if (keysPresenter.getSigningKeys().isEmpty()) {
            messageDialogFactory.showWarningDialog("error_title_no_signing_keys", "error_no_signing_keys");
            return;
        }

        SignDialog signDialog = new SignDialog(
                view.window(),
                actionListenerFactory,
                keysPresenter.getSigningKeys(),
                getJWS(),
                mode
        );
        signDialog.display();

        // If a JWS was created by the dialog, replace the contents of the editor
        JWS signedJWS = signDialog.getJWS();
        if (signedJWS != null) {
            setJWS(signedJWS);
        }
    }

    /**
     * Handle click events from the Verify button
     */
    public void onVerifyClicked() {
        List<Key> keys = ((KeysPresenter) presenters.get(KeysPresenter.class)).getVerificationKeys();

        // Check there are verification keys in the keystore
        if (keys.isEmpty()) {
            messageDialogFactory.showWarningDialog("error_title_no_verification_keys", "error_no_verification_keys");
            return;
        }

        KeyRing keyRing = new KeyRing(keys);
        Optional<Key> key = keyRing.findVerifyingKey(getJWS());

        String messageKey = key.isPresent() ? "editor_view_message_verified" : "editor_view_message_not_verified";
        Object[] args = key.map(value -> new String[]{value.getID()}).orElseGet(() -> new String[0]);

        messageDialogFactory.showWarningDialog("editor_view_message_title_verification", messageKey, args);
    }

    public void onEncryptClicked() {
        KeysPresenter keysPresenter = (KeysPresenter) presenters.get(KeysPresenter.class);

        // Check there are encryption keys in the keystore
        if (keysPresenter.getEncryptionKeys().isEmpty()) {
            messageDialogFactory.showWarningDialog("error_title_no_encryption_keys", "error_no_encryption_keys");
            return;
        }

        EncryptDialog encryptDialog = new EncryptDialog(
                view.window(),
                actionListenerFactory,
                getJWS(),
                keysPresenter.getEncryptionKeys()
        );
        encryptDialog.display();

        // If a JWE was created by the dialog, replace the contents of the editor and change to JWE mode
        JWE jwe = encryptDialog.getJWE();

        if (jwe != null) {
            view.setMode(EditorMode.JWE);
            setJWE(jwe);
        }
    }

    /**
     * Handle click events from the Decrypt button
     */
    public void onDecryptClicked() {
        KeysPresenter keysPresenter = (KeysPresenter) presenters.get(KeysPresenter.class);

        // Check there are decryption keys in the keystore
        if (keysPresenter.getDecryptionKeys().isEmpty()) {
            messageDialogFactory.showWarningDialog("error_title_no_decryption_keys", "error_no_decryption_keys");
            return;
        }

        // Attempt to decrypt the contents of the editor with all available keys
        try {
            List<Key> keys = keysPresenter.getDecryptionKeys();
            Optional<JWS> jws = new KeyRing(keys).attemptDecryption(getJWE());

            // If decryption was successful, set the contents of the editor to the decrypted JWS and set the editor mode to JWS
            if (jws.isPresent()) {
                view.setMode(EditorMode.JWS);
                setJWS(jws.get());
            } else {
                messageDialogFactory.showWarningDialog("error_title_unable_to_decrypt", "error_decryption_all_keys_failed");
            }
        } catch (ParseException e) {
            messageDialogFactory.showWarningDialog("error_title_unable_to_decrypt", "error_decryption_invalid_header");
        }
    }

    /**
     * Handle click events from the Copy button
     */
    public void onCopyClicked() {
        Utils.copyToClipboard(view.getSerialized());
    }

    /**
     * Get the message set by setMessage with the changes made by the editor
     *
     * @return the altered message
     */
    public String getMessage() {
        return model.getMessage();
    }

    /**
     * Has the editor modified any of the JOSE Objects
     *
     * @return true if changes have been made in the editor
     */
    public boolean isModified() {
        return model.isModified();
    }

    /**
     * Callback called by the view whenever the dropdown selection is changed
     */
    public void onSelectionChanged() {
        // Set a selectionChanging to true, so componentChanged doesn't treat the change as a user event
        selectionChanging = true;

        // Get the JOSEObject pair corresponding to the selected dropdown entry index
        MutableJOSEObject mutableJoseObject = model.getJOSEObject(view.getSelectedJOSEObjectIndex());
        JOSEObject joseObject = mutableJoseObject.getModified();

        // Change to JWE/JWS mode based on the newly selected JOSEObject
        if (joseObject instanceof JWS) {
            view.setMode(EditorMode.JWS);
            setJWS((JWS) joseObject);
        } else {
            view.setMode(EditorMode.JWE);
            setJWE((JWE) joseObject);
        }

        // Allow user events in componentChanged again
        selectionChanging = false;
    }

    /**
     * Callback called by the view whenever the contents of a text or hex editor changes, or the compact checkbox is modified
     */
    public void componentChanged() {
        // Get the currently selected object
        MutableJOSEObject mutableJoseObject = model.getJOSEObject(view.getSelectedJOSEObjectIndex());

        //Serialize the text/hex entries to a JWS/JWE in compact form, depending on the editor mode
        JOSEObject joseObject = view.getMode() == EditorMode.JWS ? getJWS() : getJWE();
        //Update the JOSEObjectPair with the change
        mutableJoseObject.setModified(joseObject);
        //Highlight the serialized text as changed if it differs from the original, and the change wasn't triggered by onSelectionChanging
        view.setSerialized(joseObject.serialize(), mutableJoseObject.changed() && !selectionChanging);

        List<Information> information = mutableJoseObject.timeClaims().stream()
                .map(Information::from)
                .toList();

        view.setInformation(information);
    }

    /**
     * Handle click events from the JWE Header Format button
     */
    public void formatJWEHeader() {
        try {
            view.setJWEHeader(prettyPrintJSON(view.getJWEHeader()));
        } catch (JSONException e) {
            messageDialogFactory.showErrorDialog("error_title_unable_to_format_json", "error_format_json");
        }
    }

    /**
     * Handle click events from the JWS Header Format button
     */
    public void formatJWSHeader() {
        try {
            view.setJWSHeader(prettyPrintJSON(view.getJWSHeader()));
        } catch (JSONException e) {
            messageDialogFactory.showErrorDialog("error_title_unable_to_format_json", "error_format_json");
        }
    }

    /**
     * Handle click events from the JWS Payload Format button
     */
    public void formatJWSPayload() {
        try {
            view.setPayload(prettyPrintJSON(view.getPayload()));
        } catch (JSONException e) {
            messageDialogFactory.showErrorDialog("error_title_unable_to_format_json", "error_format_json");
        }
    }
}
