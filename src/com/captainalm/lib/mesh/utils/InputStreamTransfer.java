package com.captainalm.lib.mesh.utils;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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
                if (bytesRead == - 1)
                    return pos;
                pos += bytesRead;
            }
        } catch (EOFException ignored) {
        }
        return pos;
    }

    /**
     * Reads all bytes from an {@link InputStream}, blocking if necessary.
     *
     * @param inputStream The input stream to read from.
     * @return The read in bytes or an empty byte array.
     */
    public static byte[] readAllBytes(InputStream inputStream) {
        if (inputStream == null)
            return new byte[0];
        byte[] buffer = new byte[4096];
        List<byte[]> bytesList = new ArrayList<>();
        List<Integer> sizeList = new ArrayList<>();
        int bytesRead;
        try {
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                sizeList.add(bytesRead);
                bytesList.add(buffer);
                buffer = new byte[4096];
            }
        } catch (IOException ignored) {
        }
        int sz = 0;
        for (int size : sizeList)
            sz += size;
        buffer = new byte[sz];
        int pos = 0;
        int i = 0;
        for (byte[] bytes : bytesList) {
            int len = sizeList.get(i++);
            System.arraycopy(bytes, 0, buffer, pos, len);
            pos += len;
        }
        bytesList.clear();
        sizeList.clear();
        return buffer;
    }
}
