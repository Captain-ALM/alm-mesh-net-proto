package com.captainalm.lib.mesh.packets.data;

import com.captainalm.lib.mesh.packets.Packet;
import com.captainalm.lib.mesh.utils.IP;

/**
 * Provides IP packet storage for 4/6.
 * {@link com.captainalm.lib.mesh.packets.PacketType#UnicastData}
 *
 * @author Alfred Manville
 */
public class DataPayload extends PacketData {
    protected byte[] ipPk;
    protected int ver;

    /**
     * Constructs a new instance of DataPayload from a {@link Packet}.
     *
     * @param packet The packet to construct from.
     */
    public DataPayload(Packet packet) {
        super(packet);
    }

    /**
     * Constructs a new instance of DataPayload from an IP Packet.
     *
     * @param ipPacket The IP packet to encapsulate (4/6)
     */
    public DataPayload(byte[] ipPacket) {
        super((ipPacket ==  null || ipPacket.length < 1) ? 0 : (IP.getVersionFromPacket(ipPacket) == 4) ? ipPacket.length - 8 : (((ipPacket[0] >> 4) == 6) ? ipPacket.length - 32 : 0));
        if (ipPacket != null && ipPacket.length > 0) {
            ver = IP.getVersion(ipPacket[0]);
            if (ver == 4) {
                System.arraycopy(ipPacket, 0, data, 0, 12);
                System.arraycopy(ipPacket, 20, data, 12, ipPacket.length - 20);
            } else if (ver == 6) {
                System.arraycopy(ipPacket, 0, data, 0, 8);
                System.arraycopy(ipPacket, 40, data, 8, ipPacket.length - 40);
            }
            ipPk = ipPacket;
        }
    }

    protected int actualDataLength() {
        return dataSize;
    }

    /**
     * Gets the IP packet, given the node ID addresses.
     *
     * @param sourceNodeID The source node ID.
     * @param destinationNodeID The destination node ID.
     * @return The encapsulated IP packet bytes.
     */
    public byte[] getIpPacket(byte[] sourceNodeID, byte[] destinationNodeID) {
        if (ipPk == null && actualDataLength() > 0 && sourceNodeID != null && sourceNodeID.length > 16 && destinationNodeID != null && destinationNodeID.length > 16) {
            ver = IP.getVersion(data[dataStartIndex]);
            if (ver == 4) {
                ipPk = new byte[actualDataLength() + 8];
                System.arraycopy(data, dataStartIndex, ipPk, 0, 12);
                ipPk[12] = 10; //10.x.x.x
                System.arraycopy(sourceNodeID, 0, ipPk, 13, 3);
                ipPk[16] = 10; //10.x.x.x
                System.arraycopy(destinationNodeID, 0, ipPk, 17, 4);
                System.arraycopy(data, dataStartIndex + 12, ipPk, 20, actualDataLength() - 12);
            } else if (ver == 6) {
                ipPk = new byte[actualDataLength() + 32];
                System.arraycopy(data, dataStartIndex, ipPk, 0, 8);
                ipPk[8] = (byte) 253; //fd0a::
                ipPk[9] = 10;
                System.arraycopy(sourceNodeID, sourceNodeID.length - 14, ipPk, 10, 14);
                ipPk[24] = (byte) 253; //fd0a::
                ipPk[25] = 10;
                System.arraycopy(destinationNodeID, destinationNodeID.length - 14, ipPk, 26, 14);
                System.arraycopy(data, dataStartIndex + 8, ipPk, 40, actualDataLength() - 8);
            }
        }
        return ipPk;
    }
}
