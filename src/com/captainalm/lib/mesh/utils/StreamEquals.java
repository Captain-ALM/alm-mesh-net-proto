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
}
