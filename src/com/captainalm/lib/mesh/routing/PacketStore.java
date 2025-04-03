package com.captainalm.lib.mesh.routing;

import com.captainalm.lib.mesh.packets.Packet;
import com.captainalm.lib.mesh.packets.data.SignaturePayload;

/**
 * Provides a packet store struct.
 *
 * @author Alfred Manville
 */
public final class PacketStore {
    public Packet packet;
    public SignaturePayload[] packetSignature;
    public byte[] packetHash;
    public byte[] signatureHash;
    public PacketStore newerStore;
    public PacketStore olderStore;
    public PacketStore nextFreeStore;
}
