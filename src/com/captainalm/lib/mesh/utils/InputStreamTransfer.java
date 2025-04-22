package com.captainalm.lib.mesh.utils;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Provides the ability to copy an {@link java.io.InputStream} to an {@link java.io.OutputStream}.
 *
 * @author Alfred Manville
 */
public final class InputStreamTransfer {

    /**
     * Transfers data from the provided {@link InputStream} to the {@link OutputStream}.
     *
     * @param inputStream The input stream to read from.
     * @param outputStream The output stream to transfer to.
     * @throws IOException An I/O Exception has occured.
     */
    public static void streamTransfer(InputStream inputStream, OutputStream outputStream) throws IOException {
        if (inputStream == null || outputStream == null)
            return;
        byte[] buffer = new byte[4096];
        int bytesRead;
        try {
            while ((bytesRead = inputStream.read(buffer)) != -1)
                outputStream.write(buffer, 0, bytesRead);
        } catch (EOFException ignored) {
        }
    }

    /**
     * Tries to read all the bytes from a stream until it reaches an EOF.
     *
     * @param inputStream The input stream to read from.
     * @return The number of bytes manged to read.
     * @throws IOException An I/O Exception has occured.
     */
    public static int readAllBytes(InputStream inputStream, byte[] bytes) throws IOException {
        if (inputStream == null || bytes == null)
            return 0;
        int pos = 0;
        try {
            while (pos < bytes.length) {
                int bytesRead = inputStream.read(bytes, pos, bytes.length - pos);
                pos += bytesRead;
            }
        } catch (EOFException ignored) {
        }
        return pos;
    }
}
