package com.captainalm.lib.mesh.utils;

/**
 * Provides utilities for IP 4/6 packet manipulation.
 *
 * @author Alfred Manville
 */
public class IP {
    /**
     * Gets the IP version of the packet.
     *
     * @param packet The IP packet data.
     * @return The version.
     */
    public static int getVersionFromPacket(byte[] packet) {
        if (packet ==null || packet.length == 0)
            return 0;
        return getVersion(packet[0]);
    }

    /**
     * Gets the IP version from the first IP packet byte.
     *
     * @param firstPacketByte The IP packet data's first byte.
     * @return The version.
     */
    public static int getVersion(byte firstPacketByte) {
        return firstPacketByte >> 4;
    }
    /**
     * Extracts the source address of an IP 4/6 packet.
     *
     * @param packet The IP packet data.
     * @return The source address or null if invalid.
     */
    public static byte[] extractSourceAddress(byte[] packet) {
        byte[] addr = null;
        if (packet != null && packet.length > 0) {
            int ver = getVersion(packet[0]);
            if (ver == 4 && packet.length > 19) {
                addr = new byte[4];
                System.arraycopy(packet, 12, addr, 0, 4);
            } else if (ver == 6 && packet.length > 39) {
                addr = new byte[16];
                System.arraycopy(packet, 8, addr, 0, 16);
            }
        }
        return addr;
    }

    /**
     * Extracts the destination address of an IP 4/6 packet.
     *
     * @param packet The IP packet data.
     * @return The destination address or null if invalid.
     */
    public static byte[] extractDestinationAddress(byte[] packet) {
        byte[] addr = null;
        if (packet != null && packet.length > 0) {
            int ver = getVersion(packet[0]);
            if (ver == 4 && packet.length > 19) {
                addr = new byte[4];
                System.arraycopy(packet, 16, addr, 0, 4);
            } else if (ver == 6 && packet.length > 39) {
                addr = new byte[16];
                System.arraycopy(packet, 24, addr, 0, 16);
            }
        }
        return addr;
    }
}
