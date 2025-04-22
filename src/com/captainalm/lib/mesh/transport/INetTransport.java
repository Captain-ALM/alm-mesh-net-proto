package com.captainalm.lib.mesh.transport;

import java.io.Closeable;

/**
 * Provides a generic interface for network transports.
 *
 * @author Alfred Manville
 */
public interface INetTransport extends Closeable {
    /**
     * Sends packet data.
     *
     * @param packet The packet data.
     */
    void send(byte[] packet);

    /**
     * Receives a packet.
     *
     * @return the packet data, or null when {@link #isActive()} is false.
     */
    byte[] receive();

    /**
     * De-activates the transport.
     */
    void close();

    /**
     * Gets if the transport is active.
     *
     * @return If the transport is active.
     */
    boolean isActive();

    /**
     * Signals that an encryption upgrade is ready.
     *
     * @param writingEncryptionKey The encryption key to upgrade the writer to.
     */
    void upgrade(byte[] writingEncryptionKey);
}
