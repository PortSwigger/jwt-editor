package com.blackberry.jwteditor.model.keys;

public interface KeysModelListener {
    void notifyKeyInserted(Key key);

    void notifyKeyDeleted(int rowIndex);

    void notifyKeyDeleted(Key key);

    class InertKeysModelListener implements KeysModelListener {
        @Override
        public void notifyKeyInserted(Key key) {
        }

        @Override
        public void notifyKeyDeleted(int rowIndex) {
        }

        @Override
        public void notifyKeyDeleted(Key key) {
        }
    }

    class SimpleKeysModelListener implements KeysModelListener {
        private final Runnable action;

        public SimpleKeysModelListener(Runnable action) {
            this.action = action;
        }

        @Override
        public void notifyKeyInserted(Key key) {
            action.run();
        }

        @Override
        public void notifyKeyDeleted(int rowIndex) {
            action.run();
        }

        @Override
        public void notifyKeyDeleted(Key key) {
            action.run();
        }
    }
}
