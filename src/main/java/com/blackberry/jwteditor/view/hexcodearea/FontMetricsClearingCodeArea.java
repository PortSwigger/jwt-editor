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

package com.blackberry.jwteditor.view.hexcodearea;

import burp.api.montoya.logging.Logging;
import org.exbin.deltahex.swing.CodeArea;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;

class FontMetricsClearingCodeArea extends GarbageCollectableCodeArea {
    private final Logging logging;

    FontMetricsClearingCodeArea(Logging logging) {
        this.logging = logging;
    }

    @Override
    public void updateUI() {
        super.updateUI();

        if (logging != null) {
            // Reset fontMetrics in case Burp's font size has changed
            try {
                Field paintDataCacheField = FontMetricsClearingCodeArea.class.getSuperclass().getDeclaredField("paintDataCache");
                paintDataCacheField.setAccessible(true);

                Object paintDataCacheRef = paintDataCacheField.get(this);
                Field fontMetricsField = paintDataCacheRef.getClass().getDeclaredField("fontMetrics");
                fontMetricsField.setAccessible(true);

                fontMetricsField.set(paintDataCacheRef, null);
            } catch (NoSuchFieldException | IllegalAccessException e) {
                StringWriter stringWriter = new StringWriter();
                PrintWriter printWriter = new PrintWriter(stringWriter);
                e.printStackTrace(printWriter);
                logging.logToError(stringWriter.toString());
            }

            // Reset colors in case Burp's theme has changed
            CodeArea codeArea = new GarbageCollectableCodeArea();
            setMainColors(codeArea.getMainColors());
            setAlternateColors(codeArea.getAlternateColors());
            setSelectionColors(codeArea.getSelectionColors());
            setMirrorSelectionColors(codeArea.getMirrorSelectionColors());
        }
    }
}
