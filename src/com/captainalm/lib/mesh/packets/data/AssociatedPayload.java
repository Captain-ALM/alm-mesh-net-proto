package com.captainalm.lib.mesh.packets.data;

import com.captainalm.lib.mesh.packets.Packet;
import com.captainalm.lib.mesh.utils.ByteBufferOverwriteOutputStream;

import java.io.ByteArrayInputStream;

/**
 * Provides a payload associated with an ID.
 * {@link com.captainalm.lib.mesh.packets.PacketType#DirectHandshakeKEMKey}
 * {@link com.captainalm.lib.mesh.packets.PacketType#DirectHandshakeDSAKey}
 * {@link com.captainalm.lib.mesh.packets.PacketType#BroadcastAssociateEID}
 * {@link com.captainalm.lib.mesh.packets.PacketType#BroadcastAssociateKEMKey}
 * {@link com.captainalm.lib.mesh.packets.PacketType#BroadcastAssociateDSAKey}
 *
 * @author Alfred Manville
 */
public class AssociatedPayload extends AssociatePayload {
    protected byte[] associatedPayload;

    /**
     * Constructs a new instance of AssociatedPayload from a {@link Packet}.
     *
     * @param packet The packet to construct from.
     */
    public AssociatedPayload(Packet packet) {
        super(packet);
    }

    /**
     * Create a new AssociatedPayload with the specified ID and associated payload data.
     *
     * @param ID The ID.
     * @param associatedPayload The associated payload to store.
     */
    public AssociatedPayload(byte[] ID, byte[] associatedPayload) {
        super(32 + ((associatedPayload == null) ? 0 : associatedPayload.length));
        if (associatedPayload != null) {
            this.associateID = ID;
            System.arraycopy(ID, 0, data, 0, ID.length);
        }
        if (associatedPayload != null) {
            this.associatedPayload = associatedPayload;
            System.arraycopy(associatedPayload, 0, data, 32, associatedPayload.length) ;
        }
    }

    /**
     * Create a new AssociatedPayload with the specified ID and associated payload size.
     *
     * @param ID The ID.
     * @param size The payload size.
     */
    public AssociatedPayload(byte[] ID, int size) {
        this(ID, new byte[size]);
    }

    /**
     * Gets the associated payload size.
     *
     * @return The associated payload size.
     */
    public int getAssociatedPayloadSize() {
        return dataSize - 32;
    }

    /**
     * Gets the value of the payload.
     * Modifying may not modify the underlying payload.
     *
     * @return The payload.
     */
    public byte[] getAssociatedPayload() {
        if (associatedPayload == null && dataSize > 31) {
            associatedPayload = new byte[dataSize - 32];
            System.arraycopy(data, dataStartIndex + 32, associatedPayload, 0, dataSize);
        }
        return associatedPayload;
    }

    /**
     * Sets the payload given the data.
     *
     * @param payload The payload to set to.
     * @throws IllegalArgumentException The payload is null or size does not match {@link #getSize()}-32.
     */
    public void setAssociatedPayload(byte[] payload) {
        if (payload == null || payload.length != dataSize-32)
            throw new IllegalArgumentException("payload null or size does not match");
        this.associatedPayload = payload;
        System.arraycopy(payload, 0, data, dataStartIndex+32, dataSize);
    }

    /**
     * Gets a stream to read the payload.
     *
     * @return The stream.
     */
    public ByteArrayInputStream getAssociatedPayloadStream() {
        return new ByteArrayInputStream(data, dataStartIndex+32, dataSize);
    }

    /**
     * Gets a stream to overwrite the payload.
     *
     * @return The stream.
     */
    public ByteBufferOverwriteOutputStream getAssociatedPayloadWritingStream() {
        return new ByteBufferOverwriteOutputStream(data, dataStartIndex+32, dataSize);
    }
}
