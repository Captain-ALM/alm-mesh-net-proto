package com.captainalm.lib.mesh.utils;

import java.io.IOException;
import java.io.InputStream;

/**
 * Check if two {@link java.io.InputStream}s have the same contents.
 *
 * @author Alfred Manville
 */
public class StreamEquals {
    /**
     * Checks if the contents of 2 {@link InputStream}s are equal.
     * The streams may not be fully consumed.
     *
     * @param in1 The first input.
     * @param in2 The second input.
     * @return If the streams are equal.
     * @throws IOException An I/E Error has occurred.
     */
    public static boolean streamEquals(InputStream in1, InputStream in2) throws IOException {
        if (in1 == null && in2 == null)
            return true;
        if (in1 == null || in2 == null)
            return false;
        int i1 = in1.read();
        int i2 = in2.read();
        if (i1 != i2)
            return false;
        while (i1 > -1) {
            i1 = in1.read();
            i2 = in2.read();
            if (i1 != i2)
                return false;
        }
        return true;
    }

    /**
     * Checks if the contents of an {@link InputStream} and an array are equal.
     * The stream may not be fully consumed.
     *
     * @param in The input.
     * @param array The array.
     * @return If the stream and array are equal.
     * @throws IOException An I/E Error has occurred.
     */
    public static boolean streamEqualsArray(InputStream in, byte[] array) throws IOException {
        if (in == null && array == null)
            return true;
        if (in == null || array == null)
            return false;
        int i = in.read();
        if (i == -1 && array.length == 0)
            return true;
        else if (array.length > 0) {
            if (i != Byte.toUnsignedInt(array[0]))
                return false;
            for (int j = 1; j < array.length; j++) {
                i = in.read();
                if (i == -1 || Byte.toUnsignedInt(array[j]) != i)
                    return false;
            }
            return true;
        }
        return false;
    }
}
