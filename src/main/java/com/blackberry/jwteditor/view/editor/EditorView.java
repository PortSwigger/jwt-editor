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

package com.blackberry.jwteditor.view.editor;

import burp.api.montoya.collaborator.CollaboratorPayloadGenerator;
import burp.api.montoya.ui.Selection;
import com.blackberry.jwteditor.model.jose.ClaimsType;
import com.blackberry.jwteditor.model.jose.Information;
import com.blackberry.jwteditor.model.keys.KeysRepository;
import com.blackberry.jwteditor.presenter.EditorPresenter;
import com.blackberry.jwteditor.utils.Utils;
import com.blackberry.jwteditor.view.hexcodearea.HexCodeAreaFactory;
import com.blackberry.jwteditor.view.rsta.RstaFactory;
import com.blackberry.jwteditor.view.utils.ErrorLoggingActionListenerFactory;
import com.blackberry.jwteditor.view.utils.MaxLengthStringComboBoxModel;
import com.blackberry.jwteditor.view.utils.RunEDTActionOnFirstRenderHierarchyListener;
import org.exbin.deltahex.EditationAllowed;
import org.exbin.deltahex.swing.CodeArea;
import org.exbin.utils.binary_data.ByteArrayEditableData;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.List;

import static com.blackberry.jwteditor.model.jose.ClaimsType.JSON;
import static java.awt.Color.RED;
import static java.awt.EventQueue.invokeLater;
import static org.exbin.deltahex.EditationAllowed.ALLOWED;
import static org.exbin.deltahex.EditationAllowed.READ_ONLY;

/**
 * View class for the Editor tab
 */
public abstract class EditorView {
    private static final int JWS_TAB_INDEX = 0;
    private static final int JWE_TAB_INDEX = 1;
    private static final int MAX_JOSE_OBJECT_STRING_LENGTH = 68;

    final EditorPresenter presenter;

    private final RstaFactory rstaFactory;
    private final boolean editable;
    private final HexCodeAreaFactory hexCodeAreaFactory;
    private final InformationPanel informationPanel;
    private final boolean isProVersion;

    private EditorMode mode;
    private JTabbedPane tabbedPane;
    private JComboBox<String> comboBoxJOSEObject;
    private JButton buttonSign;
    private JButton buttonEncrypt;
    private JPanel panel;
    private JPanel panelKey;
    private JPanel panelCiphertext;
    private JPanel panelIV;
    private JPanel panelTag;
    private JPanel panelSignature;
    private RSyntaxTextArea textAreaSerialized;
    private RSyntaxTextArea textAreaJWEHeader;
    private RSyntaxTextArea textAreaJWSHeader;
    private RSyntaxTextArea textAreaPayload;
    private JButton buttonDecrypt;
    private JButton buttonCopy;
    private JButton buttonAttack;
    private JButton buttonVerify;
    private JButton buttonJWSHeaderFormatJSON;
    private JCheckBox checkBoxJWSHeaderCompactJSON;
    private JButton buttonJWEHeaderFormatJSON;
    private JCheckBox checkBoxJWEHeaderCompactJSON;
    private JButton buttonJWSPayloadFormatJSON;
    private JCheckBox checkBoxJWSPayloadCompactJSON;
    private JSplitPane upperSplitPane;
    private JSplitPane midSplitPane;
    private JSplitPane lowerSplitPane;
    private JScrollPane informationScrollPane;

    private CodeArea codeAreaSignature;
    private CodeArea codeAreaEncryptedKey;
    private CodeArea codeAreaCiphertext;
    private CodeArea codeAreaIV;
    private CodeArea codeAreaTag;

    EditorView(
            KeysRepository keysRepository,
            RstaFactory rstaFactory,
            HexCodeAreaFactory hexAreaCodeFactory,
            CollaboratorPayloadGenerator collaboratorPayloadGenerator,
            ErrorLoggingActionListenerFactory actionListenerFactory,
            InformationPanelFactory informationPanelFactory,
            boolean editable,
            boolean isProVersion) {
        this.rstaFactory = rstaFactory;
        this.editable = editable;
        this.hexCodeAreaFactory = hexAreaCodeFactory;
        this.isProVersion = isProVersion;
        this.presenter = new EditorPresenter(this, collaboratorPayloadGenerator, actionListenerFactory, keysRepository);
        this.informationPanel = informationPanelFactory.build();

        informationScrollPane.setViewportView(informationPanel);

        panel.addHierarchyListener(new RunEDTActionOnFirstRenderHierarchyListener(
                panel,
                () -> {
                    upperSplitPane.setDividerLocation(0.25);
                    lowerSplitPane.setDividerLocation(0.5);
                    invokeLater(() -> midSplitPane.setDividerLocation(0.693));
                }
        ));

        // Event handler for Header / JWS payload change events
        DocumentListener documentListener = new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                presenter.componentChanged();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                presenter.componentChanged();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                presenter.componentChanged();
            }
        };

        // Attach event handlers for form elements changing, forward to presenter
        textAreaJWSHeader.getDocument().addDocumentListener(documentListener);
        textAreaPayload.getDocument().addDocumentListener(documentListener);
        codeAreaSignature.addDataChangedListener(presenter::componentChanged);
        textAreaJWEHeader.getDocument().addDocumentListener(documentListener);
        codeAreaEncryptedKey.addDataChangedListener(presenter::componentChanged);
        codeAreaCiphertext.addDataChangedListener(presenter::componentChanged);
        codeAreaTag.addDataChangedListener(presenter::componentChanged);
        codeAreaIV.addDataChangedListener(presenter::componentChanged);

        // Compact check box event handler
        checkBoxJWEHeaderCompactJSON.addActionListener(e -> presenter.componentChanged());
        checkBoxJWSHeaderCompactJSON.addActionListener(e -> presenter.componentChanged());
        checkBoxJWSPayloadCompactJSON.addActionListener(e -> presenter.componentChanged());

        // Format check box event handler
        buttonJWEHeaderFormatJSON.addActionListener(e -> presenter.formatJWEHeader());
        buttonJWSHeaderFormatJSON.addActionListener(e -> presenter.formatJWSHeader());
        buttonJWSPayloadFormatJSON.addActionListener(e -> presenter.formatJWSPayload());

        // Button click event handlers
        comboBoxJOSEObject.addActionListener(e -> presenter.onSelectionChanged());
        buttonSign.addActionListener(e -> presenter.onSignClicked());
        buttonVerify.addActionListener(e -> presenter.onVerifyClicked());
        buttonEncrypt.addActionListener(e -> presenter.onEncryptClicked());
        buttonDecrypt.addActionListener(e -> presenter.onDecryptClicked());
        buttonCopy.addActionListener(e -> presenter.onCopyClicked());
    }

    /**
     * Handler for Attack button
     */
    private void onAttackClicked() {
        // Display the attack popup menu
        JPopupMenu popupMenu = buttonAttack.getComponentPopupMenu();
        popupMenu.setVisible(false);
        // Position to above attack button
        buttonAttack.getComponentPopupMenu().show(buttonAttack, buttonAttack.getX(), buttonAttack.getY());
        buttonAttack.getComponentPopupMenu().show(
                buttonAttack,
                buttonAttack.getX(),
                buttonAttack.getY() - buttonAttack.getComponentPopupMenu().getHeight()
        );
    }

    public void setJWSHeader(String header) {
        textAreaJWSHeader.setText(header);
    }

    /**
     * Get the JWS header value from the UI
     * @return value string
     */
    public String getJWSHeader() {
        return textAreaJWSHeader.getText();
    }

    public void setPayload(String payload, ClaimsType claimsType) {
        boolean claimIsJson = claimsType == JSON;

        buttonJWSPayloadFormatJSON.setEnabled(claimIsJson);
        checkBoxJWSPayloadCompactJSON.setEnabled(claimIsJson);

        textAreaPayload.setText(payload);
    }

    /**
     * Get the payload value from the UI
     * @return value string
     */
    public String getPayload() {
        return textAreaPayload.getText();
    }

    /**
     * Set the JWS signature in the UI
     * @param signature signature bytes
     */
    public void setSignature(byte[] signature) {
        codeAreaSignature.setData(new ByteArrayEditableData(signature));
    }

    /**
     * Set the JWE header value in the UI
     * @param header value string
     */
    public void setJWEHeader(String header) {
        textAreaJWEHeader.setText(header);
    }

    /**
     * Get the JWE header value from the UI
     * @return value string
     */
    public String getJWEHeader() {
        return textAreaJWEHeader.getText();
    }

    /**
     * Set the encrypted key in the UI
     * @param encryptionKey value bytes
     */
    public void setEncryptedKey(byte[] encryptionKey) {
        codeAreaEncryptedKey.setData(new ByteArrayEditableData(encryptionKey));
    }

    /**
     * Get the encrypted key from the UI
     * @return encrypted key bytes
     */
    public byte[] getEncryptedKey() {
        return Utils.getCodeAreaData(codeAreaEncryptedKey);
    }

    /**
     * Set the ciphertext in the UI
     * @param ciphertext ciphertext bytes
     */
    public void setCiphertext(byte[] ciphertext) {
        codeAreaCiphertext.setData(new ByteArrayEditableData(ciphertext));
    }

    /**
     * Get the ciphertext from the UI
     * @return ciphertext bytes
     */
    public byte[] getCiphertext() {
        return Utils.getCodeAreaData(codeAreaCiphertext);
    }

    /**
     * Set the tag in the UI
     * @param tag tag bytes
     */
    public void setTag(byte[] tag) {
        codeAreaTag.setData(new ByteArrayEditableData(tag));
    }

    /**
     * Get the tag from the UI
     * @return tag bytes
     */
    public byte[] getTag() {
        return Utils.getCodeAreaData(codeAreaTag);
    }

    /**
     * Set the IV value in the UI
     * @param iv iv bytes
     */
    public void setIV(byte[] iv) {
        codeAreaIV.setData(new ByteArrayEditableData(iv));
    }

    /**
     * Get the IV value from the UI
     * @return iv bytes
     */
    public byte[] getIV() {
        return Utils.getCodeAreaData(codeAreaIV);
    }

    /**
     * Get the signature value from the UI
     * @return signature bytes
     */
    public byte[] getSignature() {
        return Utils.getCodeAreaData(codeAreaSignature);
    }

    public void setSerialized(String text, boolean textModified) {
        textAreaSerialized.setText(text);

        Border serializedTextAreaBorder = textModified ? new LineBorder(RED, 1) : null;
        textAreaSerialized.setBorder(serializedTextAreaBorder);
    }

    /**
     * Get the serialised JWS/JWE from the UI
     * @return serialised JWE/JWS
     */
    public String getSerialized() {
        return textAreaSerialized.getText();
    }

    /**
     * Set the JWS/JWEs in the UI dropdown
     * @param joseObjectStrings array of JWS/JWE to display
     */
    public void setJOSEObjects(List<String> joseObjectStrings) {
        comboBoxJOSEObject.setModel(new MaxLengthStringComboBoxModel(MAX_JOSE_OBJECT_STRING_LENGTH, joseObjectStrings));

        if (!joseObjectStrings.isEmpty()) {
            comboBoxJOSEObject.setSelectedIndex(0);
        }
    }

    /**
     * Get the index of the currently selected JWS/JWE
     * @return selected JWS/JWE index
     */
    public int getSelectedJOSEObjectIndex() {
        return comboBoxJOSEObject.getSelectedIndex();
    }

    /**
     * Get the UI mode - JWS or JWE
     * @return UI mode value
     */
    public EditorMode getMode() {
        return mode;
    }

    public void setMode(EditorMode mode)
    {
        this.mode = mode;

        if (mode == EditorMode.JWS) {
            configureUIForJWS();
        } else {
            configureUIForJWE();
        }
    }

    private void configureUIForJWS() {
        tabbedPane.setSelectedIndex(JWS_TAB_INDEX);
        tabbedPane.setEnabledAt(JWS_TAB_INDEX, true);
        tabbedPane.setEnabledAt(JWE_TAB_INDEX, false);
        buttonAttack.setEnabled(editable);
        buttonSign.setEnabled(editable);
        buttonVerify.setEnabled(true);
        buttonEncrypt.setEnabled(editable);
        buttonDecrypt.setEnabled(false);
        buttonJWEHeaderFormatJSON.setEnabled(false);
        buttonJWSHeaderFormatJSON.setEnabled(editable);
        buttonJWSPayloadFormatJSON.setEnabled(editable);
        checkBoxJWEHeaderCompactJSON.setEnabled(false);
        checkBoxJWSHeaderCompactJSON.setEnabled(editable);
        checkBoxJWSPayloadCompactJSON.setEnabled(editable);
        textAreaJWSHeader.setEditable(editable);
        textAreaPayload.setEditable(editable);
        codeAreaSignature.setEditationAllowed(editable ? ALLOWED : READ_ONLY);
    }

    private void configureUIForJWE() {
        tabbedPane.setSelectedIndex(JWE_TAB_INDEX);
        tabbedPane.setEnabledAt(JWS_TAB_INDEX, false);
        tabbedPane.setEnabledAt(JWE_TAB_INDEX, true);
        buttonAttack.setEnabled(false);
        buttonSign.setEnabled(false);
        buttonVerify.setEnabled(false);
        buttonEncrypt.setEnabled(false);
        buttonDecrypt.setEnabled(editable);
        buttonJWEHeaderFormatJSON.setEnabled(editable);
        buttonJWSHeaderFormatJSON.setEnabled(false);
        buttonJWSPayloadFormatJSON.setEnabled(false);
        checkBoxJWEHeaderCompactJSON.setEnabled(editable);
        checkBoxJWSHeaderCompactJSON.setEnabled(false);
        checkBoxJWSPayloadCompactJSON.setEnabled(false);

        textAreaJWEHeader.setEditable(editable);
        textAreaJWEHeader.setEnabled(editable);

        EditationAllowed editationAllowed = editable ? ALLOWED : READ_ONLY;

        codeAreaEncryptedKey.setEditationAllowed(editationAllowed);
        codeAreaIV.setEditationAllowed(editationAllowed);
        codeAreaCiphertext.setEditationAllowed(editationAllowed);
        codeAreaTag.setEditationAllowed(editationAllowed);
    }

    /**
     * Set the Compact checkbox for the JWS header
     * @param compact the compact value
     */
    public void setJWSHeaderCompact(boolean compact) {
        checkBoxJWSHeaderCompactJSON.setSelected(compact);
    }

    /**
     * Get the Compact checkbox for the JWS header
     * @return the compact value
     */
    public boolean getJWSHeaderCompact() {
        return checkBoxJWSHeaderCompactJSON.isSelected();
    }

    /**
     * Set the Compact checkbox for the JWS payload
     * @param compact the compact value
     */
    public void setJWSPayloadCompact(boolean compact) {
        checkBoxJWSPayloadCompactJSON.setSelected(compact);
    }

    /**
     * Get the Compact checkbox for the JWS payload
     * @return the compact value
     */
    public boolean getJWSPayloadCompact() {
        return checkBoxJWSPayloadCompactJSON.isSelected();
    }

    /**
     * Set the Compact checkbox for the JWE header
     * @param compact the compact value
     */
    public void setJWEHeaderCompact(boolean compact) {
        checkBoxJWEHeaderCompactJSON.setSelected(compact);
    }

    /**
     * Get the Compact checkbox for the JWE header
     * @return the compact value
     */
    public boolean getJWEHeaderCompact() {
        return checkBoxJWEHeaderCompactJSON.isSelected();
    }

    public String caption() {
        return Utils.getResourceString("burp_editor_tab");
    }

    public Component uiComponent() {
        return panel;
    }

    public Selection selectedData() {
        return null;
    }

    /**
     * Has the message been altered by the extension
     * @return true if the extension has altered the message
     */
    public boolean isModified() {
        return presenter.isModified();
    }

    /**
     * Get the view's parent Window
     * @return parent Window
     */
    public Window window() {
        return SwingUtilities.getWindowAncestor(panel);
    }

    /**
     * Custom view initialisation
     */
    private void createUIComponents() {
        panelSignature = new JPanel(new BorderLayout());
        codeAreaSignature = hexCodeAreaFactory.build();
        panelSignature.add(codeAreaSignature);

        panelKey = new JPanel(new BorderLayout());
        codeAreaEncryptedKey = hexCodeAreaFactory.build();
        panelKey.add(codeAreaEncryptedKey, BorderLayout.CENTER);

        panelCiphertext = new JPanel(new BorderLayout());
        codeAreaCiphertext = hexCodeAreaFactory.build();
        panelCiphertext.add(codeAreaCiphertext, BorderLayout.CENTER);

        panelIV = new JPanel(new BorderLayout());
        codeAreaIV = hexCodeAreaFactory.build();
        panelIV.add(codeAreaIV, BorderLayout.CENTER);

        panelTag = new JPanel(new BorderLayout());
        codeAreaTag = hexCodeAreaFactory.build();
        panelTag.add(codeAreaTag, BorderLayout.CENTER);

        // Create the Attack popup menu
        JPopupMenu popupMenuAttack = new JPopupMenu();
        JMenuItem menuItemAttackEmbedJWK = new JMenuItem(Utils.getResourceString("editor_view_button_attack_embed_jwk"));
        JMenuItem menuItemAttackSignNone = new JMenuItem(Utils.getResourceString("editor_view_button_attack_sign_none"));
        JMenuItem menuItemAttackKeyConfusion = new JMenuItem(Utils.getResourceString("editor_view_button_attack_key_confusion"));
        JMenuItem menuItemAttackSignEmptyKey = new JMenuItem(Utils.getResourceString("editor_view_button_attack_sign_empty_key"));
        JMenuItem menuItemAttackSignPsychicSignature = new JMenuItem(Utils.getResourceString("editor_view_button_attack_sign_psychic_signature"));
        JMenuItem menuItemAttackEmbedCollaboratorPayload = new JMenuItem(Utils.getResourceString("editor_view_button_attack_embed_collaborator_payload"));

        // Attach the event handlers to the popup menu click events
        menuItemAttackEmbedJWK.addActionListener(e -> presenter.onAttackEmbedJWKClicked());
        menuItemAttackKeyConfusion.addActionListener(e -> presenter.onAttackKeyConfusionClicked());
        menuItemAttackSignNone.addActionListener(e -> presenter.onAttackSignNoneClicked());
        menuItemAttackSignEmptyKey.addActionListener(e -> presenter.onAttackSignEmptyKeyClicked());
        menuItemAttackSignPsychicSignature.addActionListener(e -> presenter.onAttackPsychicSignatureClicked());
        menuItemAttackEmbedCollaboratorPayload.addActionListener(e -> presenter.onAttackEmbedCollaboratorPayloadClicked());

        menuItemAttackEmbedCollaboratorPayload.setEnabled(isProVersion);

        // Add the buttons to the popup menu
        popupMenuAttack.add(menuItemAttackEmbedJWK);
        popupMenuAttack.add(menuItemAttackSignNone);
        popupMenuAttack.add(menuItemAttackKeyConfusion);
        popupMenuAttack.add(menuItemAttackSignEmptyKey);
        popupMenuAttack.add(menuItemAttackSignPsychicSignature);
        popupMenuAttack.add(menuItemAttackEmbedCollaboratorPayload);

        // Associate the popup menu to the Attack button
        buttonAttack = new JButton();
        buttonAttack.setComponentPopupMenu(popupMenuAttack);
        buttonAttack.addActionListener(e -> onAttackClicked());

        textAreaSerialized = rstaFactory.buildSerializedJWTTextArea();
        textAreaJWEHeader = rstaFactory.buildDefaultTextArea();
        textAreaJWSHeader = rstaFactory.buildDefaultTextArea();
        textAreaPayload = rstaFactory.buildDefaultTextArea();
    }

    public void setInformation(List<Information> information) {
        informationPanel.updateInformation(information);
    }
}
