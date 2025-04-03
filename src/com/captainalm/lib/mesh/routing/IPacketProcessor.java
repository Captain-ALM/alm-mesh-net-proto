package com.captainalm.lib.mesh.routing;

import com.captainalm.lib.mesh.packets.Packet;

/**
 * Provides a packet processing interface.
 *
 * @author Alfred Manville
 */
public interface IPacketProcessor {
    /**
     * Receives a packet.
     *
     * @param packet The received packet.
     */
    void processPacket(Packet packet);

    /**
     * Send the router instance.
     *
     * @param router Gives the router instance to the processor.
     */
    void obtainRouter(Router router);
}
