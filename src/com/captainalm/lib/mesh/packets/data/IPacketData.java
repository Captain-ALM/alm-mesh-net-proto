package com.captainalm.lib.mesh.packets.data;

/**
 * Provides an interface for packet data.
 *
 * @author Alfred Manville
 */
public interface IPacketData {
    /**
     * Gets the packet data as a payload.
     *
     * @return The packet data bytes.
     */
    byte[] getPacketPayload();

    /**
     * Gets the size of the packet payload.
     *
     * @return The number of packet data bytes.
     */
    int getPacketLength();
}
