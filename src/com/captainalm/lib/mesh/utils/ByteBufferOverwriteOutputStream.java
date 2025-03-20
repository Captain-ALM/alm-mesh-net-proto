package com.captainalm.lib.mesh.utils;

import java.io.IOException;
import java.io.OutputStream;

/**
 * This class provides the ability to overwrite parts of a byte array using {@link java.io.OutputStream} methods.
 *
 * @author Alfred Manville
 */
public class ByteBufferOverwriteOutputStream extends OutputStream {
    protected byte[] buffer;
    protected int pos; //Inclusive, stores start / current
    protected int maxPos; //Exclusive

    /**
     * Constructs a new instance of ByteBufferOverwriteOutputStream with the specified underlying buffer
     * start position and overwrite length.
     *
     * @param buffer The buffer to use.
     * @param pos The position to start the overwrite at.
     * @param maxLength The length of the over-writable area.
     * @throws IllegalArgumentException pos is out of bounds.
     */
    public ByteBufferOverwriteOutputStream(byte[] buffer, int pos, int maxLength) {
        this.buffer = buffer;
        if (pos < 0 || pos >= buffer.length) throw new IllegalArgumentException("pos is out of bounds");
        this.pos = pos;
        this.maxPos = Math.min(pos + maxLength, buffer.length);
    }

    /**
     * Writes the specified byte to this output stream. The general
     * contract for {@code write} is that one byte is written
     * to the output stream. The byte to be written is the eight
     * low-order bits of the argument {@code b}. The 24
     * high-order bits of {@code b} are ignored.
     * <p>
     * Subclasses of {@code OutputStream} must provide an
     * implementation for this method.
     *
     * @param      b   the {@code byte}.
     * @throws     IOException  if an I/O error occurs. In particular,
     *             an {@code IOException} may be thrown if the
     *             output stream has been closed.
     */
    @Override
    public void write(int b) throws IOException {
        if (buffer == null) throw new IOException("stream closed");
        if (pos >= maxPos) throw new IOException("buffer full");
        buffer[pos++] = (byte) b;
    }

    /**
     * Resets the start of overwrite position and overwrite length.
     *
     * @param pos The position to start the overwrite at.
     * @param maxLength The length of the over-writable area.
     * @throws IllegalArgumentException pos is out of bounds.
     */
    public void reset(int pos, int maxLength) {
        if (pos < 0 || pos >= maxPos) throw new IllegalArgumentException("pos is out of bounds");
        this.pos = pos;
        this.maxPos = Math.min(pos + maxLength, buffer.length);
    }

    /**
     * Returns if the buffer is full.
     *
     * @return If the current buffer position is greater than or equal to the limit.
     */
    public boolean bufferFull() {
        return pos >= maxPos;
    }

    /**
     * Closes the stream, removing the buffer reference from itself.
     *
     * @exception  IOException  if an I/O error occurs.
     */
    @Override
    public void close() throws IOException {
        if (buffer != null) buffer = null;
        super.close();
    }
}
