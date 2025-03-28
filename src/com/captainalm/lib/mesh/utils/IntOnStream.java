package com.captainalm.lib.mesh.utils;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Provides utility functions to read and write integer types
 * to {@link java.io.OutputStream}s or from {@link java.io.InputStream}s.
 *
 * @author Alfred Manville
 */
public final class IntOnStream {
    /**
     * Writes a positive short to a stream.
     *
     * @param out The {@link OutputStream} to write to.
     * @param value The value to write.
     * @throws IOException An I/O Error has occurred.
     * @throws IllegalArgumentException out is null or value is negative.
     */
    public static void WriteShort(OutputStream out, short value) throws IOException {
        if (out == null)
            throw new IllegalArgumentException("out is null");
        if (value < 0)
            throw new IllegalArgumentException("value less than 0");
        out.write((byte) (value / 256));
        value %= 256;
        out.write((byte) value);
    }

    /**
     * Writes a positive int to a stream.
     *
     * @param out The {@link OutputStream} to write to.
     * @param value The value to write.
     * @throws IOException An I/O Error has occurred.
     * @throws IllegalArgumentException out is null or value is negative.
     */
    public static void WriteInt(OutputStream out, int value) throws IOException {
        if (out == null)
            throw new IllegalArgumentException("out is null");
        if (value < 0)
            throw new IllegalArgumentException("value less than 0");
        out.write((byte) (value / (256 * 256 * 256)));
        value %= (256 * 256 * 256);
        out.write((byte) (value / (256 * 256)));
        value %= (256 * 256);
        WriteShort(out, (short) value);
    }

    /**
     * Writes a positive long to a stream.
     *
     * @param out The {@link OutputStream} to write to.
     * @param value The value to write.
     * @throws IOException An I/O Error has occurred.
     * @throws IllegalArgumentException out is null or value is negative.
     */
    public static void WriteLong(OutputStream out, long value) throws IOException {
        if (out == null)
            throw new IllegalArgumentException("out is null");
        if (value < 0)
            throw new IllegalArgumentException("value less than 0");
        long divs = 256L * 256L * 256L * 256L * 256L * 256L * 256L; // divisor
        while (divs > 256L * 256L * 256L) {
            out.write((byte) (value / divs));
            value %= divs;
            divs /= 256L;
        }
        WriteInt(out, (int) value);
    }

    static int ReadStream(InputStream in) throws IOException {
        int read = in.read();
        if (read < 0)
            throw new EOFException();
        return read;
    }

    /**
     * Reads a short from a stream.
     *
     * @param in The {@link InputStream} to read from.
     * @return The read value.
     * @throws EOFException End of stream has been reached.
     * @throws IOException An I/O Error has occurred.
     */
    public static short ReadShort(InputStream in) throws IOException {
        if (in == null)
            throw new IllegalArgumentException("in is null");
        short value = (short) (ReadStream(in) * 256);
        return (short) (value + (short) ReadStream(in));
    }

    /**
     * Reads an int from a stream.
     *
     * @param in The {@link InputStream} to read from.
     * @return The read value.
     * @throws EOFException End of stream has been reached.
     * @throws IOException An I/O Error has occurred.
     */
    public static int ReadInt(InputStream in) throws IOException {
        if (in == null)
            throw new IllegalArgumentException("in is null");
        int value = ReadStream(in) * 256 * 256 * 256;
        int mult = 256 * 256; // multiplier
        while (mult > 1) {
            value += ReadStream(in) * mult;
            mult /= 256;
        }
        return value + ReadStream(in);
    }

    /**
     * Reads a long from a stream.
     *
     * @param in The {@link InputStream} to read from.
     * @return The read value.
     * @throws EOFException End of stream has been reached.
     * @throws IOException An I/O Error has occurred.
     */
    public static long ReadLong(InputStream in) throws IOException {
        if (in == null)
            throw new IllegalArgumentException("in is null");
        long value = (long) ReadStream(in) * 256L * 256L * 256L * 256L * 256L * 256L * 256L;
        long mult = 256L * 256L * 256L * 256L * 256L * 256L; // multiplier
        while (mult > 1) {
            value += (long) ReadStream(in) * mult;
            mult /= 256L;
        }
        return value + (long) ReadStream(in);
    }
}
