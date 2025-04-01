package com.captainalm.lib.mesh.packets.data;

import com.captainalm.lib.mesh.packets.Packet;

/**
 * Provides addressed IP packet storage for 4/6.
 * {@link com.captainalm.lib.mesh.packets.PacketType#UnicastDataAddressed}
 *
 * @author Alfred Manville
 */
public class DataAddressedPayload extends DataPayload {
    protected boolean treatAddressAsSender;

    /**
     * Constructs a new instance of DataAddressedPayload from a {@link Packet}.
     *
     * @param packet The packet to construct from.
     * @param isSender Treat the tag address as sender.
     */
    public DataAddressedPayload(Packet packet, boolean isSender) {
        super(packet);
        treatAddressAsSender = isSender;
    }

    /**
     * Constructs a new instance of DataAddressedPayload from an IP Packet.
     *
     * @param ipPacket The IP packet to encapsulate (4/6)
     * @param isSender Treat the tag address as sender.
     */
    public DataAddressedPayload(byte[] ipPacket, boolean isSender) {
        super(ipPacket);
        treatAddressAsSender = isSender;
    }

    @Override
    protected int actualDataLength() {
        return super.actualDataLength() - 16;
    }

    /**
     * Gets the IP packet, given the node ID addresses.
     * The Node ID is ignored where the tagged address gets set to.
     *
     * @param sourceNodeID The source node ID.
     * @param destinationNodeID The destination node ID.
     * @return The encapsulated IP packet bytes.
     */
    @Override
    public byte[] getIpPacket(byte[] sourceNodeID, byte[] destinationNodeID) {
        if (dataSize < 16)
            return ipPk;
        if (super.getIpPacket(sourceNodeID, destinationNodeID) != null) {
            if (treatAddressAsSender) {
                if (ver == 4) {
                    System.arraycopy(data, dataSize - 16 + dataStartIndex, ipPk, 12, 4);
                } else if (ver == 6) {
                    System.arraycopy(data, dataSize - 16 + dataStartIndex, ipPk, 8, 16);
                }
            } else {
                if (ver == 4) {
                    System.arraycopy(data, dataSize - 16 + dataStartIndex, ipPk, 16, 4);
                } else if (ver == 6) {
                    System.arraycopy(data, dataSize - 16 + dataStartIndex, ipPk, 24, 16);
                }
            }
        }
        return ipPk;
    }
}
