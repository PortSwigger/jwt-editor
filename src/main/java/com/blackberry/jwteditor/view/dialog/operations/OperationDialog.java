/*

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

package com.blackberry.jwteditor.view.dialog.operations;

import burp.api.montoya.logging.Logging;
import com.blackberry.jwteditor.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import static com.blackberry.jwteditor.view.dialog.operations.OperationPanel.VALIDITY_EVENT;
import static java.awt.Dialog.ModalityType.APPLICATION_MODAL;
import static javax.swing.JOptionPane.WARNING_MESSAGE;

public class OperationDialog<T, U> extends JDialog {
    private final String errorTitleOperationFailed;
    private final Logging logging;
    private final Operation<T, U> operation;
    private final U originalJwt;
    private final JPanel panel;
    private final PropertyChangeListener propertyChangeListener;

    private JPanel contentPane;
    private JPanel mainPanel;
    private JButton buttonOK;
    private JButton buttonCancel;

    private T jwt;

    public OperationDialog(Window parent, Logging logging, Operation<T, U> operation, U jwt) {
        super(parent, Utils.getResourceString(operation.titleResourceId()), APPLICATION_MODAL);

        this.logging = logging;
        this.operation = operation;
        this.originalJwt = jwt;
        this.errorTitleOperationFailed = operation.operationFailedResourceId();

        setContentPane(contentPane);
        getRootPane().setDefaultButton(buttonOK);

        buttonOK.addActionListener(e -> onOK());
        buttonCancel.addActionListener(e -> onCancel());

        // call onCancel() on ESCAPE
        contentPane.registerKeyboardAction(
                e -> onCancel(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT
        );

        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);

        setMinimumSize(operation.dimension());
        setPreferredSize(operation.dimension());
        panel = operation.configPanel();
        propertyChangeListener = new ValidityWatcher();
        mainPanel.add(panel);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                onCancel();
            }
        });

        panel.addPropertyChangeListener(VALIDITY_EVENT, propertyChangeListener);
    }

    public T getJWT() {
        return jwt;
    }

    public void display() {
        pack();
        setLocationRelativeTo(getOwner());
        setVisible(true);
    }

    void onOK() {
        try {
            jwt = operation.performOperation(originalJwt);
        } catch (Exception e) {
            String title = Utils.getResourceString(errorTitleOperationFailed);
            logging.logToError(title, e);
            JOptionPane.showMessageDialog(
                    this,
                    e.getMessage(),
                    title,
                    WARNING_MESSAGE
            );
            jwt = null;
        } finally {
            onCancel();
        }
    }

    void onCancel() {
        dispose();
        panel.removePropertyChangeListener(VALIDITY_EVENT, propertyChangeListener);
    }

    private class ValidityWatcher implements PropertyChangeListener {
        @Override
        public void propertyChange(PropertyChangeEvent evt) {
            if (!evt.getPropertyName().equals(VALIDITY_EVENT) || !(evt.getNewValue() instanceof Boolean)) {
                return;
            }

            boolean isValid = (Boolean) evt.getNewValue();
            buttonOK.setEnabled(isValid);
        }
    }
}
