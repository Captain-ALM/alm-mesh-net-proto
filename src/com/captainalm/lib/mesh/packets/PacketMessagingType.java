package com.captainalm.lib.mesh.packets;

/**
 * Provides the type of packet messaging.
 *
 * @author Alfred Manville
 */
public enum PacketMessagingType {
    /**
     * A non routed link packet.
     */
    Direct,
    /**
     * A routed packet to any destinations.
     */
    Broadcast,
    /**
     * A routed packet to one destination.
     */
    Unicast;
}
