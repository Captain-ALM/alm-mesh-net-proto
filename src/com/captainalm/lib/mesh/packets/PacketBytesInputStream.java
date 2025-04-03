package com.captainalm.lib.mesh.packets;

import com.captainalm.lib.mesh.utils.ByteBufferOverwriteOutputStream;
import com.captainalm.lib.mesh.utils.IntOnStream;
import com.captainalm.lib.mesh.utils.LengthClampedInputStream;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Provides obtaining packet bytes from an {@link InputStream}.
 *
 * @author Alfred Manville
 */
public final class PacketBytesInputStream implements Closeable {
    private final InputStream in;
    private final byte[] readHeader = new byte[2];
    private byte[] buffer;

    /**
     * Constructs a new PacketBytesInputStream with the specified input stream.
     *
     * @param in The {@link InputStream} to use.
     * @throws NullPointerException in is null.
     */
    public PacketBytesInputStream(InputStream in) {
        if (in == null)
            throw new NullPointerException("in is null");
        this.in = in;
    }

    /**
     * Reads in the next packet bytes.
     *
     * @return The data bytes of the next packet.
     * @throws EOFException The end of stream has been reached.
     * @throws IOException An I/O error has occurred.
     */
    public byte[] readNext() throws IOException {
        int read = in.read(readHeader);
        if (read != 2) {
            in.close();
            throw new EOFException();
        }
        short sz = IntOnStream.ReadShort(in);
        buffer = new byte[sz + 4];
        ByteBufferOverwriteOutputStream ovrw = new ByteBufferOverwriteOutputStream(buffer, 0, buffer.length);
        ovrw.write(readHeader);
        IntOnStream.WriteShort(ovrw, sz);
        new LengthClampedInputStream(in, sz).transferTo(ovrw);
        return buffer;
    }

    /**
     * Closes the underlying stream and releases any system resources associated
     * with it. If the stream is already closed then invoking this
     * method has no effect.
     *
     * <p> As noted in {@link AutoCloseable#close()}, cases where the
     * close may fail require careful attention. It is strongly advised
     * to relinquish the underlying resources and to internally
     * <em>mark</em> the {@code Closeable} as closed, prior to throwing
     * the {@code IOException}.
     *
     * @throws IOException if an I/O error occurs
     */
    @Override
    public void close() throws IOException {
        in.close();
    }
}
