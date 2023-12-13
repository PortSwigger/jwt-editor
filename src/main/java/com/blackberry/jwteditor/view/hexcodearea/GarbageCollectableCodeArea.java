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

import org.exbin.deltahex.swing.CodeArea;
import org.exbin.deltahex.swing.CodeAreaCaret;

import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;

public class GarbageCollectableCodeArea extends CodeArea {
    private static final int DEFAULT_BLINK_RATE = 450;

    public GarbageCollectableCodeArea() {
        CodeAreaCaret caret = getCaret();
        caret.setBlinkRate(0);

        addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {
                caret.setBlinkRate(DEFAULT_BLINK_RATE);
            }

            @Override
            public void focusLost(FocusEvent e) {
                caret.setBlinkRate(0);
            }
        });
    }
}
