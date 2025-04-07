/*
Author : Dolph Flynn

Copyright 2025 Dolph Flynn

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

import com.blackberry.jwteditor.utils.Utils;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import java.awt.*;

import static javax.swing.BorderFactory.*;

class SingleComboBoxPanel<T> extends JPanel {
    private static final Color TITLE_COLOR = new Color(187, 187, 187);

    private final JComboBox<T> comboBox;

    SingleComboBoxPanel(String titleResourceId, T[] options) {
        this(titleResourceId, options, options[0]);
    }

    SingleComboBoxPanel(String titleResourceId, T[] options, T selectedItem) {
        super(new GridBagLayout());

        JPanel panel = new JPanel(new BorderLayout());

        TitledBorder titledBorder = new TitledBorder(createLineBorder(TITLE_COLOR), Utils.getResourceString(titleResourceId));
        titledBorder.setTitleColor(TITLE_COLOR);

        Border emptyBorder = createEmptyBorder(2, 5, 5, 5);

        panel.setBorder(createCompoundBorder(titledBorder, emptyBorder));

        comboBox = new JComboBox<>();
        comboBox.setModel(new DefaultComboBoxModel<>(options));
        comboBox.setSelectedItem(selectedItem);

        panel.add(comboBox);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.FIRST_LINE_START;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        add(panel, gbc);
    }

    T selectedItem() {
        return (T) comboBox.getSelectedItem();
    }
}
