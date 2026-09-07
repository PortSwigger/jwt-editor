/*
Author : Dolph Flynn

Copyright 2026 Dolph Flynn

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

package com.blackberry.jwteditor.pem;

import org.bouncycastle.util.io.pem.PemObject;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;

import static com.blackberry.jwteditor.pem.PemKey.NewLineStrategy.SYSTEM_DEFAULT;

public class PemKey {
    private final PemObject pemObject;

    public PemKey(PemObject pemObject) {
        this.pemObject = pemObject;
    }

    @Override
    public String toString() {
        return toString(SYSTEM_DEFAULT);
    }

    public String toString(NewLineStrategy newLineStrategy) {
        StringWriter stringWriter = new StringWriter();

        try (PemWriter pemWriter = new PemWriter(stringWriter, newLineStrategy)) {
            pemWriter.writeObject(pemObject);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        return stringWriter.toString();
    }

    public enum NewLineStrategy {
        LINUX_MACOS("Linux / MacOS (0x0A)"),
        LINUX_MACOS_NO_TRAILING_LINE("Linux / MacOS (0x0A) - no trailing newline"),
        WINDOWS("Windows (0x0D0A)"),
        WINDOWS_NO_TRAILING_LINE("Windows (0x0D0A) - no trailing newline"),
        SYSTEM_DEFAULT("System Default");

        private final String displayName;

        NewLineStrategy(String displayName) {
            this.displayName = displayName;
        }

        public String newLine() {
            return switch (this) {
                case LINUX_MACOS, LINUX_MACOS_NO_TRAILING_LINE -> "\n";
                case WINDOWS, WINDOWS_NO_TRAILING_LINE -> "\r\n";
                case SYSTEM_DEFAULT -> System.lineSeparator();
            };
        }

        public boolean writeTrailingNewline() {
            return switch (this) {
                case LINUX_MACOS, WINDOWS, SYSTEM_DEFAULT -> true;
                case LINUX_MACOS_NO_TRAILING_LINE, WINDOWS_NO_TRAILING_LINE -> false;
            };
        }

        @Override
        public String toString() {
            return displayName;
        }
    }
}
