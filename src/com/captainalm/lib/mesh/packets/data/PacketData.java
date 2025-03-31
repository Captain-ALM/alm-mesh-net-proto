package com.captainalm.lib.mesh.packets.data;

import com.captainalm.lib.mesh.packets.Packet;

import java.io.ByteArrayInputStream;

/**
 * Provides a base class for all {@link  Packet} payloads.
 *
 * @author Alfred Manville
 */
public abstract class PacketData {
    protected byte[] data;
    protected int dataStartIndex;
    protected int dataSize;

    /**
     * Constructs a new instance of PacketData from a {@link Packet}.
     *
     * @param packet The packet to construct from.
     */
    public PacketData(Packet packet) {
        data = packet.getPacketBytes();
        dataStartIndex = packet.getPacketDataStartIndex();
        dataSize = packet.getPayloadSize();
    }

    /**
     * Constructs a new instance of PacketData of a specified size.
     *
     * @param size The size of the packet payload.
     */
    public PacketData(int size) {
        data = new byte[size];
        dataStartIndex = 0;
        dataSize = size;
    }

    /**
     * Gets the packet payload data.
     *
     * @return The data as a {@link  ByteArrayInputStream}.
     */
    public ByteArrayInputStream getData() {
        return new ByteArrayInputStream(data, dataStartIndex, dataSize);
    }

    /**
     * Gets the size of the payload.
     *
     * @return The size of the payload.
     */
    public int getSize() {
        return dataSize;
    }
}
