package com.captainalm.lib.mesh.packets;

/**
 * Provides a broadcast packet representation which has a source address.
 *
 * @author Alfred Manville
 */
public class BroadcastPacket extends Packet {
    public static final int MIN_SIZE = 76;

    /**
     * Creates a broadcast packet from its data representation.
     *
     * @param packet The packet data.
     */
    public BroadcastPacket(byte[] packet) {
        super(packet);
    }

    /**
     * Creates a broadcast new packet with a specified payload size.
     *
     * @param size The size of the payload.
     */
    public BroadcastPacket(int size) {
        super(size);
    }

    /**
     * Gets the payload start index in the packet.
     *
     * @return The payload start index.
     */
    @Override
    public int getPacketDataStartIndex() {
        return super.getPacketDataStartIndex() + 32;
    }

    /**
     * Gets the source address of the packet.
     *
     * @return The source address.
     */
    public byte[] getSourceAddress() {
        byte[] addr = new byte[32];
        if (data == null || data.length < 76) return addr;
        System.arraycopy(data, 12, addr, 0, 32);
        return addr;
    }

    /**
     * Sets the source address of the packet.
     *
     * @param addr The source address.
     * @return This instance of Packet.
     */
    public BroadcastPacket setSourceAddress(byte[] addr) {
        if (addr == null || addr.length != 32 || data == null || data.length < 76) return this;
        System.arraycopy(addr, 0, data, 12, 32);
        return this;
    }
}
