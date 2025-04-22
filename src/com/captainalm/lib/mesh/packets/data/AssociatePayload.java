package com.captainalm.lib.mesh.packets.data;

import com.captainalm.lib.mesh.packets.Packet;

/**
 * Provides an ID payload.
 * {@link com.captainalm.lib.mesh.packets.PacketType#BroadcastNodeDead}
 * {@link com.captainalm.lib.mesh.packets.PacketType#BroadcastDeAssociateEID}
 *
 * @author Alfred Manville
 */
public class AssociatePayload extends PacketData {
    protected byte[] associateID;

    /**
     * Constructs a new instance of AssociatePayload with the specified ID.
     *
     * @param ID The payload to store.
     */
    public AssociatePayload(byte[] ID) {
        super((ID == null || ID.length < 32) ? new byte[0] : ID);
        associateID = ID;
    }

    /**
     * Constructs a new instance of AssociatePayload from a {@link Packet}.
     *
     * @param packet The packet to construct from.
     */
    public AssociatePayload(Packet packet) {
        super(packet);
    }

    protected AssociatePayload(int size) {
        super(size);
    }

    /**
     * Gets the associate ID.
     *
     * @return The ID associated.
     */
    public byte[] getAssociateID() {
        if (associateID == null && dataSize > 31) {
            associateID = new byte[32];
            System.arraycopy(data, dataStartIndex, associateID, 0, 32);
        }
        return associateID;
    }
}
