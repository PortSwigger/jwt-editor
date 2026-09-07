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

import com.blackberry.jwteditor.pem.PemKey.NewLineStrategy;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;

// Based on BouncyCastle PemWriter - https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/util/io/pem/PemWriter.java and RFC 1421
class PemWriter extends BufferedWriter {
    private static final int LINE_LENGTH = 64;

    private final char[] buf;
    private final NewLineStrategy newLineStrategy;

    PemWriter(Writer out, NewLineStrategy newLineStrategy) {
        super(out);

        this.newLineStrategy = newLineStrategy;
        this.buf = new char[LINE_LENGTH];
    }

    void writeObject(PemObjectGenerator objectGenerator) throws IOException {
        PemObject pemObject = objectGenerator.generate();

        this.write("-----BEGIN %s-----%s".formatted(pemObject.getType(), newLineStrategy.newLine()));

        if (!pemObject.getHeaders().isEmpty()) {
            for (Object o : pemObject.getHeaders()) {
                PemHeader header = (PemHeader) o;

                // A CR or LF in a header name or value would inject extra header lines, or a blank
                // line would terminate the header block early -- a PEM header injection. Reject it.
                if (hasLineBreak(header.getName()) || hasLineBreak(header.getValue())) {
                    throw new IllegalArgumentException("PEM header must not contain CR/LF");
                }

                this.write("%s: %s%s".formatted(header.getName(), header.getValue(), newLineStrategy.newLine()));
            }

            this.newLine();
        }

        writeEncoded(pemObject.getContent());
        this.write("-----END %s-----".formatted(pemObject.getType()));

        if (newLineStrategy.writeTrailingNewline()) {
            this.write(newLineStrategy.newLine());
        }
    }

    private void writeEncoded(byte[] bytes) throws IOException {
        bytes = Base64.encode(bytes);

        for (int i = 0; i < bytes.length; i += buf.length) {
            int index = 0;

            while (index != buf.length) {
                if ((i + index) >= bytes.length) {
                    break;
                }
                buf[index] = (char) bytes[i + index];
                index++;
            }
            this.write(buf, 0, index);
            this.newLine();
        }
    }

    @Override
    public void newLine() throws IOException {
        write(newLineStrategy.newLine());
    }

    private static boolean hasLineBreak(String s) {
        return s != null && (s.indexOf('\r') >= 0 || s.indexOf('\n') >= 0);
    }
}
