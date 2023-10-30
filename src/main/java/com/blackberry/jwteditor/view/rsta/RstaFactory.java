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

package com.blackberry.jwteditor.view.rsta;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import com.blackberry.jwteditor.view.rsta.jwt.JWTTokenMaker;
import com.blackberry.jwteditor.view.rsta.jwt.JWTTokenizerConstants;
import com.blackberry.jwteditor.view.utils.FontProvider;
import org.fife.ui.rsyntaxtextarea.AbstractTokenMakerFactory;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.TokenMakerFactory;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.util.function.Supplier;

import static com.blackberry.jwteditor.view.rsta.CustomTokenColors.customTokenColors;
import static com.blackberry.jwteditor.view.rsta.jwt.JWTTokenMaker.*;
import static com.blackberry.jwteditor.view.rsta.jwt.JWTTokenizerConstants.MAPPING;
import static com.blackberry.jwteditor.view.rsta.jwt.JWTTokenizerConstants.TOKEN_MAKER_FQCN;

public class RstaFactory {
    private final DarkModeDetector darkModeDetector;
    private final FontProvider fontProvider;
    private final Logging logging;

    public RstaFactory(UserInterface userInterface, Logging logging) {
        this.darkModeDetector = new DarkModeDetector(userInterface);
        this.fontProvider = new FontProvider(userInterface);
        this.logging = logging;

        AbstractTokenMakerFactory tokenMakerFactory = (AbstractTokenMakerFactory) TokenMakerFactory.getDefaultInstance();
        tokenMakerFactory.putMapping(MAPPING, TOKEN_MAKER_FQCN);
        JWTTokenMaker.errorLogger = logging::logToError;
    }

    public RSyntaxTextArea buildDefaultTextArea() {
        return fixKeyEventCapture(
                () -> new CustomizedRSyntaxTextArea(darkModeDetector, fontProvider, logging::logToError)
        );
    }

    public RSyntaxTextArea buildSerializedJWTTextArea() {
        CustomTokenColors customTokenColors = customTokenColors()
                .withForeground(JWT_PART1, Color.decode("#FB015B"))
                .withForeground(JWT_PART2, Color.decode("#D63AFF"))
                .withForeground(JWT_PART3, Color.decode("#00B9F1"))
                .withForeground(JWT_PART4, Color.decode("#EA7600"))
                .withForeground(JWT_PART5, Color.decode("#EDB219"))
                .withForeground(JWT_SEPARATOR1, Color.decode("#A6A282"))
                .withForeground(JWT_SEPARATOR2, Color.decode("#A6A282"))
                .withForeground(JWT_SEPARATOR3, Color.decode("#A6A282"))
                .withForeground(JWT_SEPARATOR4, Color.decode("#A6A282"))
                .build();

        RSyntaxTextArea textArea = fixKeyEventCapture(
                () -> new CustomizedRSyntaxTextArea(
                        darkModeDetector,
                        fontProvider,
                        logging::logToError,
                        customTokenColors
                )
        );

        textArea.setSyntaxEditingStyle(JWTTokenizerConstants.MAPPING);

        return textArea;
    }

    // Ensure Burp key events not captured - https://github.com/bobbylight/RSyntaxTextArea/issues/269#issuecomment-776329702
    private RSyntaxTextArea fixKeyEventCapture(Supplier<RSyntaxTextArea> rSyntaxTextAreaSupplier) {
        JTextComponent.removeKeymap("RTextAreaKeymap");

        RSyntaxTextArea textArea = rSyntaxTextAreaSupplier.get();

        UIManager.put("RSyntaxTextAreaUI.actionMap", null);
        UIManager.put("RSyntaxTextAreaUI.inputMap", null);
        UIManager.put("RTextAreaUI.actionMap", null);
        UIManager.put("RTextAreaUI.inputMap", null);

        return textArea;
    }
}
