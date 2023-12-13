/*
Author : Dolph Flynn

Copyright 2023 Dolph Flynn

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

import com.blackberry.jwteditor.view.utils.FontProvider;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Theme;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.util.function.Consumer;

import static com.blackberry.jwteditor.view.rsta.CustomTokenColors.customTokenColors;
import static java.awt.event.HierarchyEvent.SHOWING_CHANGED;
import static org.fife.ui.rsyntaxtextarea.Theme.load;

class CustomizedRSyntaxTextArea extends RSyntaxTextArea {
    private static final String DARK_THEME = "/org/fife/ui/rsyntaxtextarea/themes/dark.xml";
    private static final String LIGHT_THEME = "/org/fife/ui/rsyntaxtextarea/themes/default.xml";
    private static final double LINE_HEIGHT_SCALING_FACTOR = 1.15;

    private final DarkModeDetector darkModeDetector;
    private final FontProvider fontProvider;
    private final Consumer<String> errorLogger;
    private final CustomTokenColors customTokenColors;

    CustomizedRSyntaxTextArea(
            DarkModeDetector darkModeDetector,
            FontProvider fontProvider,
            Consumer<String> errorLogger) {
        this(darkModeDetector, fontProvider, errorLogger, customTokenColors().build());
    }

    CustomizedRSyntaxTextArea(
            DarkModeDetector darkModeDetector,
            FontProvider fontProvider,
            Consumer<String> errorLogger,
            CustomTokenColors customTokenColors) {
        this.darkModeDetector = darkModeDetector;
        this.fontProvider = fontProvider;
        this.errorLogger = errorLogger;
        this.customTokenColors = customTokenColors;

        this.addHierarchyListener(e -> {
            if (e.getChangeFlags() == SHOWING_CHANGED && e.getComponent().isShowing()) {
                applyThemeAndFont();
                stopBracketMatchingTimer();
            }
        });

        setUseFocusableTips(false);
        setBracketMatchingEnabled(false);
        setShowMatchedBracketPopup(false);
        setAnimateBracketMatching(false);
    }

    private void stopBracketMatchingTimer() {
        try {
            Field bracketRepaintTimer = CustomizedRSyntaxTextArea.class.getSuperclass().getDeclaredField("bracketRepaintTimer");
            bracketRepaintTimer.setAccessible(true);

            Object bracketRepaintTimerRef = bracketRepaintTimer.get(this);

            if (bracketRepaintTimerRef instanceof Timer timer) {
                timer.stop();
            }
        } catch (NoSuchFieldException | IllegalAccessException e) {
            StringWriter stringWriter = new StringWriter();
            PrintWriter printWriter = new PrintWriter(stringWriter);
            e.printStackTrace(printWriter);
            errorLogger.accept(stringWriter.toString());
        }
    }

    @Override
    public String getToolTipText(MouseEvent e) {
        return null;
    }

    @Override
    protected String getToolTipTextImpl(MouseEvent e) {
        return null;
    }

    @Override
    public void setSyntaxEditingStyle(String styleKey) {
        super.setSyntaxEditingStyle(styleKey);
        applyThemeAndFont();
    }

    @Override
    public void updateUI() {
        super.updateUI();
        applyThemeAndFont();
    }

    @Override
    public Color getForegroundForTokenType(int type) {
        return customTokenColors
                .foregroundForTokenType(type)
                .orElse(super.getForegroundForTokenType(type));
    }

    @Override
    public int getLineHeight() {
        return (int) (super.getLineHeight() * LINE_HEIGHT_SCALING_FACTOR);
    }

    private void applyThemeAndFont() {
        if (errorLogger == null || fontProvider == null) {
            return;
        }

        String themeResource = darkModeDetector.isDarkMode() ? DARK_THEME : LIGHT_THEME;

        try {
            Theme theme = load(getClass().getResourceAsStream(themeResource));
            theme.apply(this);

            Font font = fontProvider.editorFont();
            setFont(font);
        } catch (IOException e) {
            errorLogger.accept(e.getMessage());
        }
    }
}
