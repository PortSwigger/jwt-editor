package com.blackberry.jwteditor.utils;

import java.util.Arrays;

public class ByteArrayUtils {

    /**
     * Trim a byte[] to an expected length
     *
     * @param bytes          input byte[]
     * @param expectedLength expected length
     * @return trimmed byte[]
     */
    public static byte[] trimByteArray(byte[] bytes, int expectedLength) {
        return Arrays.copyOfRange(bytes, 0, expectedLength);
    }
}
