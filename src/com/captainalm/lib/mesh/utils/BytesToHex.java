package com.captainalm.lib.mesh.utils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * This class contains a function found from a stackoverflow article for converting a byte array to a hexadecimal string.
 *
 * <p>
 * https://stackoverflow.com/a/9855338
 * https://stackoverflow.com/questions/9655181/java-convert-a-byte-array-to-a-hex-string/9855338#9855338
 * </p>
 * @author maybeWeCouldStealAVan, Evgeniy Berezovsky
 */
public class BytesToHex {
    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);

    /**
     * Converts a byte array to a hexadecimal string.
     *
     * @param bytes The byte array to convert.
     * @return The hexadecimal string.
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0)
            return "";
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }

    /**
     * Converts a number of bytes in an input stream into a hexadecimal array.
     * (Based off the previous function {@link #bytesToHex(byte[])})
     *
     * @param stream The stream to read from.
     * @param length The number of bytes to convert.
     * @return The hexadecimal string.
     */
    public static String bytesToHexFromStreamWithSize(InputStream stream, int length) throws IOException {
        if (stream == null)
            return "";
        byte[] hexChars = new byte[length * 2];
        for (int j = 0; j < length; j++) {
            int w = stream.read();
            if (w < 0)
                return "";
            int v = w & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }
}
