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

package com.blackberry.jwteditor.view.weak;

import burp.api.montoya.logging.Logging;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.operations.weak.WeakSecretFinder;
import com.blackberry.jwteditor.operations.weak.WeakSecretsFinderModel;
import com.blackberry.jwteditor.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Timer;
import java.util.TimerTask;

import static com.blackberry.jwteditor.operations.weak.WeakSecretsFinderStatus.CANCELLED;
import static java.awt.Dialog.ModalityType.APPLICATION_MODAL;
import static java.awt.EventQueue.invokeLater;
import static javax.swing.JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT;

public class WeakKeyAttackDialog extends JDialog {
    private final Timer timer;
    private final WeakSecretsFinderModel model;
    private final WeakSecretFinder secretFinder;

    private JPanel contentPane;
    private JButton buttonAction;
    private JProgressBar progressBar;
    private JButton buttonCopy;
    private JTextField textFieldSecret;
    private JLabel labelMessage;

    public WeakKeyAttackDialog(Window parent, Logging logging, JWS jws) {
        super(parent, "Weak HMAC Secret Attack", APPLICATION_MODAL);

        this.timer = new Timer();
        this.model = new WeakSecretsFinderModel();

        setContentPane(contentPane);
        getRootPane().setDefaultButton(buttonAction);

        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                close();
            }
        });

        buttonAction.addActionListener(e -> onAction());
        buttonCopy.addActionListener(e -> onCopy());
        buttonCopy.setEnabled(false);
        textFieldSecret.setBorder(null);

        contentPane.registerKeyboardAction(
                e -> onAction(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                WHEN_ANCESTOR_OF_FOCUSED_COMPONENT
        );

        timer.scheduleAtFixedRate(new UpdateTask(), 100, 100);

        this.secretFinder = new WeakSecretFinder(model, logging);
        secretFinder.bruteForce(jws);
    }

    private void onCopy() {
        Utils.copyToClipboard(model.secret());
        labelMessage.setText("Secret copied.");
    }

    private void onAction() {
        switch (model.status()) {
            case RUNNING -> model.setStatus(CANCELLED);
            case FAILED, CANCELLED, SUCCESS -> close();
        }
    }

    private void close() {
        timer.cancel();
        secretFinder.close();

        setVisible(false);
        dispose();
    }

    public void display() {
        pack();
        setLocationRelativeTo(getOwner());
        setVisible(true);
    }

    private class UpdateTask extends TimerTask {

        @Override
        public void run() {
            switch (model.status()) {
                case RUNNING -> invokeLater(() -> progressBar.setValue(model.progress()));

                case SUCCESS -> invokeLater(() -> {
                    progressBar.setValue(100);
                    buttonAction.setText("Close");

                    String secret = model.secret();

                    if (secret == null) {
                        labelMessage.setText("Unable to find secret.");
                    } else {
                        textFieldSecret.setText(secret);
                        buttonCopy.setEnabled(true);
                    }
                });

                case CANCELLED -> invokeLater(() -> {
                    buttonAction.setText("Close");
                    labelMessage.setText("Attack cancelled.");
                });

                case FAILED -> invokeLater(() -> {
                    progressBar.setValue(model.progress());
                    buttonAction.setText("Close");
                    labelMessage.setText("Attack failed.");
                });
            }
        }
    }
}
