package com.captainalm.lib.mesh.packets;

import com.captainalm.lib.mesh.crypto.ICryptor;
import com.captainalm.lib.mesh.utils.ByteBufferOverwriteOutputStream;
import com.captainalm.lib.mesh.utils.InputStreamTransfer;
import com.captainalm.lib.mesh.utils.IntOnStream;
import com.captainalm.lib.mesh.utils.LengthClampedInputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/**
 * Provides obtaining packet bytes from an {@link InputStream}.
 *
 * @author Alfred Manville
 */
public final class PacketBytesInputStream implements Closeable {
    private InputStream in;
    private final byte[] readHeader = new byte[2];
    private byte[] buffer;
    private boolean upgraded = false;
    private boolean nextReadUpgrades = false;
    /**
     * If set allows for auto stream upgrades to {@link javax.crypto.CipherInputStream}.
     */
    public ICryptor upgradeCipher;

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
        if (nextReadUpgrades) {
            nextReadUpgrades = false;
            if (upgradeCipher != null) {
                byte[] IV = new byte[16];
                int n = in.read(IV);
                if (n == 16) {
                    upgraded = true;
                    try {
                        in = new CipherInputStream(in, upgradeCipher.getCipher(Cipher.DECRYPT_MODE, IV));
                    } catch (GeneralSecurityException e) {
                        throw new IOException(e);
                    }
                } else
                    throw new EOFException();
            }
        }
        int read = in.read(readHeader);
        if (read != 2) {
            in.close();
            throw new EOFException();
        }
        if (readHeader[1] == PacketType.DirectHandshakeAccept.getID() && !upgraded)
            nextReadUpgrades = true;
        short sz = IntOnStream.ReadShort(in);
        buffer = new byte[sz + 4 + 32];
        ByteBufferOverwriteOutputStream ovrw = new ByteBufferOverwriteOutputStream(buffer, 0, buffer.length);
        ovrw.write(readHeader);
        IntOnStream.WriteShort(ovrw, sz);
        InputStreamTransfer.streamTransfer(new LengthClampedInputStream(in, sz + 32), ovrw);
        return buffer;
    }

    public String getBufferMetaString() {
        if (buffer == null || buffer.length < 4) {
            return ((readHeader[0] < 0) ? (int) readHeader[0] + 256 : readHeader[0]) + ","
                    + ((readHeader[1] < 0) ? (int) readHeader[1] + 256 : readHeader[1]);
        }
        String toret = "";
        for (int i = 0; i < Math.min(12,buffer.length); i++)
            toret += ((buffer[i] < 0) ? (int) buffer[i] + 256 : buffer[i]) + ",";
        if (toret.isEmpty())
            return "";
        return toret.substring(0, toret.length() - 1);
    }

    /**
     * Gets if the internal {@link InputStream} has been wrapped with an {@link CipherInputStream}.
     *
     * @return If the stream has been upgraded.
     */
    public boolean isUpgraded() {
        return upgraded || nextReadUpgrades;
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
