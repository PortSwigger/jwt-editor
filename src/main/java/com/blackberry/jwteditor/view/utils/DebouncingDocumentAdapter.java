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

package com.blackberry.jwteditor.view.utils;

import com.blackberry.jwteditor.view.utils.DocumentAdapter.DocumentAction;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.concurrent.atomic.AtomicReference;

public class DebouncingDocumentAdapter implements DocumentListener {
    private static final int DELAY_MS = 250;

    private final DocumentAction action;
    private final AtomicReference<DocumentEvent> eventReference;
    private final Timer timer;

    public DebouncingDocumentAdapter(DocumentAction action) {
        this.action = action;
        this.eventReference = new AtomicReference<>();
        this.timer = new Timer(DELAY_MS, new TimerExpiredAction());
    }

    @Override
    public void insertUpdate(DocumentEvent e) {
        storeEventAndStartTimer(e);
    }

    @Override
    public void removeUpdate(DocumentEvent e) {
        storeEventAndStartTimer(e);
    }

    @Override
    public void changedUpdate(DocumentEvent e) {
        storeEventAndStartTimer(e);
    }

    private void storeEventAndStartTimer(DocumentEvent event) {
        eventReference.set(event);
        timer.restart();
    }

    private class TimerExpiredAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            timer.stop();

            DocumentEvent documentEvent = eventReference.getAndSet(null);

            if (documentEvent != null) {
                action.documentUpdated(documentEvent);
            }
        }
    }
}