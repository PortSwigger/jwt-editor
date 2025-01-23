/*

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

import javax.swing.*;
import java.awt.*;

abstract class OperationPanel<T, U> extends JPanel implements Operation<T, U> {
    protected static final String VALIDITY_EVENT = "validityEvent";

    private static final Dimension DEFAULT_DIMENSION = new Dimension(324, 184);

    private final Dimension dimension;
    private final String titleResourceId;

    OperationPanel(String titleResourceId) {
        this(titleResourceId, DEFAULT_DIMENSION);
    }

    OperationPanel(String titleResourceId, Dimension dimension) {
        super(new BorderLayout());

        this.titleResourceId = titleResourceId;
        this.dimension = dimension;
    }

    @Override
    public JPanel configPanel() {
        return this;
    }

    @Override
    public String titleResourceId() {
        return titleResourceId;
    }

    @Override
    public Dimension dimension() {
        return dimension;
    }
}
