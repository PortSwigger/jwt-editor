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

package com.blackberry.jwteditor.view.dialog;

import com.blackberry.jwteditor.utils.Utils;

import javax.swing.*;
import java.awt.*;

import static javax.swing.JOptionPane.ERROR_MESSAGE;
import static javax.swing.JOptionPane.WARNING_MESSAGE;

public class MessageDialogFactory {
    private final Component parent;

    public MessageDialogFactory(Component parent) {
        this.parent = parent;
    }

    public void showErrorDialog(String titleKey, String messageKey, Object... args) {
        showDialog(ERROR_MESSAGE, titleKey, messageKey, args);
    }

    public void showWarningDialog(String titleKey, String messageKey, Object... args) {
        showDialog(WARNING_MESSAGE, titleKey, messageKey, args);
    }

    private void showDialog(int messageType, String titleKey, String messageKey, Object... args) {
        JOptionPane.showMessageDialog(
                parent,
                Utils.getResourceString(messageKey).formatted(args),
                Utils.getResourceString(titleKey),
                messageType
        );
    }
}
