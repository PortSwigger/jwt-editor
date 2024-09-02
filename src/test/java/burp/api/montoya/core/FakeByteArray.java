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

package burp.api.montoya.core;

import java.util.Iterator;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;

public class FakeByteArray implements ByteArray {
    private final byte[] data;

    public FakeByteArray(String data) {
        this(data.getBytes(UTF_8));
    }

    public FakeByteArray(byte[] data) {
        this.data = data;
    }

    @Override
    public byte getByte(int index) {
        return data[index];
    }

    @Override
    public void setByte(int index, byte value) {
        data[index] = value;
    }

    @Override
    public void setByte(int index, int value) {
        setByte(index, (byte) (0xFF & value));
    }

    @Override
    public void setBytes(int index, byte... data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setBytes(int index, int... data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setBytes(int index, ByteArray byteArray) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int length() {
        return data.length;
    }

    @Override
    public byte[] getBytes() {
        return data;
    }

    @Override
    public ByteArray subArray(int startIndexInclusive, int endIndexExclusive) {
        if (startIndexInclusive < 0 || endIndexExclusive <= startIndexInclusive || endIndexExclusive > data.length) {
            throw new IllegalArgumentException("Invalid indices (%d, %d) for array of length %d".formatted(startIndexInclusive, endIndexExclusive, data.length));
        }

        int length = endIndexExclusive - startIndexInclusive;
        byte[] subArray = new byte[length];
        System.arraycopy(data, startIndexInclusive, subArray, 0, length);

        return new FakeByteArray(subArray);
    }

    @Override
    public ByteArray subArray(Range range) {
        throw new UnsupportedOperationException();
    }

    @Override
    public ByteArray copy() {
        throw new UnsupportedOperationException();
    }

    @Override
    public ByteArray copyToTempFile() {
        throw new UnsupportedOperationException();
    }

    @Override
    public int indexOf(ByteArray searchTerm) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int indexOf(String searchTerm) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int indexOf(ByteArray searchTerm, boolean caseSensitive) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int indexOf(String searchTerm, boolean caseSensitive) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int indexOf(ByteArray searchTerm, boolean caseSensitive, int startIndexInclusive, int endIndexExclusive) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int indexOf(String searchTerm, boolean caseSensitive, int startIndexInclusive, int endIndexExclusive) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int indexOf(Pattern pattern) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int indexOf(Pattern pattern, int startIndexInclusive, int endIndexExclusive) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int countMatches(ByteArray searchTerm) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int countMatches(String searchTerm) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int countMatches(ByteArray searchTerm, boolean caseSensitive) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int countMatches(String searchTerm, boolean caseSensitive) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int countMatches(ByteArray searchTerm, boolean caseSensitive, int startIndexInclusive, int endIndexExclusive) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int countMatches(String searchTerm, boolean caseSensitive, int startIndexInclusive, int endIndexExclusive) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int countMatches(Pattern pattern) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int countMatches(Pattern pattern, int startIndexInclusive, int endIndexExclusive) {
        throw new UnsupportedOperationException();
    }

    @Override
    public ByteArray withAppended(byte... data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public ByteArray withAppended(int... data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public ByteArray withAppended(String text) {
        throw new UnsupportedOperationException();
    }

    @Override
    public ByteArray withAppended(ByteArray byteArray) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Iterator<Byte> iterator() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String toString() {
        return new String(data, UTF_8);
    }
}
