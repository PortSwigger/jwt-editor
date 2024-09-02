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

package com.blackberry.jwteditor.view.editor;

import burp.api.montoya.logging.Logging;
import com.blackberry.jwteditor.presenter.Information;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import static java.awt.EventQueue.invokeLater;

class InformationPanel extends JTextPane {
    private final Supplier<Font> fontSupplier;
    private final Logging logging;
    private final List<Information> informationList;
    private final Style informationStyle;
    private final Style warningStyle;
    private final Style lineSpacingStyle;

    InformationPanel(Supplier<Font> fontSupplier, Logging logging) {
        this.fontSupplier = fontSupplier;
        this.logging = logging;
        this.informationList = new ArrayList<>();
        this.informationStyle = addStyle("informationStyleName", null);
        this.warningStyle = addStyle("warningStyleName", null);
        this.lineSpacingStyle = addStyle("lineSpacingStyleName", null);

        setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 5));
        setEditable(false);

        configureStyles();
    }

    void updateInformation(List<Information> infoList) {
        invokeLater(() -> {
            informationList.clear();
            informationList.addAll(infoList);
            updateDocument();
        });
    }

    private void configureStyles() {
        Font font = fontSupplier.get();

        StyleConstants.setFontFamily(informationStyle, font.getFamily());
        StyleConstants.setFontSize(informationStyle, font.getSize());

        StyleConstants.setFontFamily(warningStyle, font.getFamily());
        StyleConstants.setFontSize(warningStyle, font.getSize());
        StyleConstants.setForeground(warningStyle, Color.RED);

        StyleConstants.setFontFamily(lineSpacingStyle, font.getFamily());
        StyleConstants.setFontSize(lineSpacingStyle, Math.round(font.getSize() * 0.3F));
    }

    private void updateDocument() {
        setText("");

        try {
            for (Information information : informationList) {
                addInformation(information);
            }
        } catch (BadLocationException e) {
            logging.logToError(e);
        }
    }

    private void addInformation(Information information) throws BadLocationException {
        StyledDocument document = getStyledDocument();

        document.insertString(document.getLength(), "• ", informationStyle);

        Style style = information.isWarning() ? warningStyle : informationStyle;
        document.insertString(document.getLength(), information.text() + "\n", style);

        document.insertString(document.getLength(), "\n", lineSpacingStyle);
    }

    @Override
    public void updateUI() {
        super.updateUI();

        if (fontSupplier != null) {
            configureStyles();
            updateDocument();
        }
    }
}
