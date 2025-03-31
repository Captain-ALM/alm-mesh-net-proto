package com.captainalm.lib.mesh.packets.layer;

import com.captainalm.lib.mesh.packets.Packet;
import com.captainalm.lib.mesh.packets.PacketMessagingType;
import com.captainalm.lib.mesh.packets.UnicastPacket;

/**
 * Provides a DataLayer.
 *
 * @author Alfred Manville
 */
public class DataLayer extends OnionLayer {

    /**
     * Creates a new DataLayer from existing data.
     *
     * @param data The data buffer.
     * @param dataStartIndex The start index of the layer.
     * @param dataSize The size of the layer.
     */
    public DataLayer(byte[] data, int dataStartIndex, int dataSize) {
        super(data, dataStartIndex, dataSize);
    }

    /**
     * Creates a new DataLayer from a packet.
     *
     * @param packet The packet to convert.
     */
    public DataLayer(Packet packet) {
        super(new byte[packet.getPayloadSize() + 121], 0, packet.getPayloadSize() + 121);
        if (packet.getType().getMessagingType() != PacketMessagingType.Unicast)
            throw new IllegalArgumentException("packet type must be Unicast");
        data[0] = packet.getPacketBytes()[1];
        System.arraycopy(packet.getPacketBytes(), 4, data, 33, 88 + packet.getPayloadSize()); // Copy from timestamp, exclude hash
    }

    /**
     * Gets the sub-layer.
     *
     * @return null as this is a packet container.
     */
    @Override
    public OnionLayer getSubLayer() {
        return null;
    }

    /**
     * Gets the encapsulated packet.
     *
     * @return The encapsulated packet.
     */
    public Packet getPacket() {
        Packet packet = new UnicastPacket(dataSize - 121);
        packet.getPacketBytes()[0] = (byte) 254;
        packet.getPacketBytes()[1] = data[dataStartIndex];
        System.arraycopy(data, dataStartIndex, packet.getPacketBytes(), 4, 88 + packet.getPayloadSize());
        return packet;
    }
}
