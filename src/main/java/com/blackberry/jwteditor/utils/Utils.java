/*
Author : Fraser Winterborn

Copyright 2021 BlackBerry Limited

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

package com.blackberry.jwteditor.utils;

import org.exbin.deltahex.swing.CodeArea;
import org.exbin.utils.binary_data.BinaryData;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.ResourceBundle;
import java.util.regex.Pattern;

import static com.blackberry.jwteditor.model.jose.JOSEObjectFinder.BASE64_REGEX;

/**
 * Class containing general util methods used throughout the other classes
 */
public class Utils {
    private static final String RESOURCE_BUNDLE = "strings"; //NON-NLS
    private static final Pattern HEX_PATTERN = Pattern.compile("^([0-9a-fA-F]{2})+$"); //NON-NLS
    private static final Pattern BASE64_PATTERN = Pattern.compile(String.format("^%s+$", BASE64_REGEX)); //NON-NLS

    /**
     * Copy a String to the default system clipboard
     *
     * @param text String to copy to the clipboard
     */
    public static void copyToClipboard(String text) {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(new StringSelection(text), null);
    }

    /**
     * Does a string contain valid hexadecimal
     *
     * @param string string to check
     * @return true if the string contains a valid sequence of hex characters
     */
    public static boolean isHex(String string) {
        return HEX_PATTERN.matcher(string).matches();
    }

    /**
     * Does a string contain only valid base64url characters
     *
     * @param string string to check
     * @return true if the string contains a valid sequence of characters that may be base64url encoded
     */
    public static boolean isBase64URL(String string) {
        return BASE64_PATTERN.matcher(string).matches();
    }

    /**
     * Get a localised string from the resource bundle
     *
     * @param id resource bundle id
     * @return corresponding string
     */
    public static String getResourceString(String id) {
        return ResourceBundle.getBundle(RESOURCE_BUNDLE).getString(id);
    }

    /**
     * Get data from a deltahex CodeArea as a byte[]
     *
     * @param codeArea CodeArea to extract bytes from
     * @return byte[] contents of the CodeArea
     */
    public static byte[] getCodeAreaData(CodeArea codeArea) {
        BinaryData binaryData = codeArea.getData();
        int size = (int) binaryData.getDataSize();
        byte[] data = new byte[size];
        binaryData.copyToArray(0L, data, 0, size);
        return data;
    }
}
