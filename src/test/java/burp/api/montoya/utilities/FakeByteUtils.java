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

package burp.api.montoya.utilities;

import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;

public class FakeByteUtils implements ByteUtils {
    @Override
    public int indexOf(byte[] bytes, byte[] bytes1) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int indexOf(byte[] bytes, byte[] bytes1, boolean b) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int indexOf(byte[] bytes, byte[] bytes1, boolean b, int i, int i1) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int indexOf(byte[] data, Pattern pattern) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int indexOf(byte[] data, Pattern pattern, int from, int to) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int countMatches(byte[] bytes, byte[] bytes1) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int countMatches(byte[] bytes, byte[] bytes1, boolean b) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int countMatches(byte[] bytes, byte[] bytes1, boolean b, int i, int i1) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int countMatches(byte[] data, Pattern pattern) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int countMatches(byte[] data, Pattern pattern, int from, int to) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String convertToString(byte[] bytes) {
        return new String(bytes, UTF_8);
    }

    @Override
    public byte[] convertFromString(String s) {
        throw new UnsupportedOperationException();
    }
}
