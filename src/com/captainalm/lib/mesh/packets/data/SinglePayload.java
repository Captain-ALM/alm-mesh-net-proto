package com.captainalm.lib.mesh.packets.data;

import com.captainalm.lib.mesh.packets.Packet;
import com.captainalm.lib.mesh.utils.ByteBufferOverwriteOutputStream;

import java.io.ByteArrayInputStream;

/**
 * Provides the ability to store a single value as a payload.
 * {@link com.captainalm.lib.mesh.packets.PacketType#DirectHandshakeDSARecommendationKey}
 * {@link com.captainalm.lib.mesh.packets.PacketType#DirectHandshakeAccept}
 * {@link com.captainalm.lib.mesh.packets.PacketType#UnicastEncryptionRequestHandshake}
 * {@link com.captainalm.lib.mesh.packets.PacketType#UnicastEncryptionResponseHandshake}
 * {@link com.captainalm.lib.mesh.packets.PacketType#UnicastOnionCircuitRejected}
 * {@link com.captainalm.lib.mesh.packets.PacketType#UnicastOnionCircuitBroken}
 *
 * @author Alfred Manville
 */
public class SinglePayload extends PacketData {
    byte[] payload;

    /**
     * Constructs a new instance of PacketData from a {@link Packet}.
     *
     * @param packet The packet to construct from.
     */
    public SinglePayload(Packet packet) {
        super(packet);
    }

    /**
     * Constructs a new instance of SinglePayload with the specified payload size.
     *
     * @param size The size of the payload data.
     */
    public SinglePayload(int size) {
        super(size);
    }

    /**
     * Constructs a new instance of SinglePayload with the specified payload data.
     *
     * @param data The data stored.
     */
    public SinglePayload(byte[] data) {
        super(data);
        payload = data;
    }

    /**
     * Gets the value of the payload.
     * Modifying may not modify the underlying payload.
     *
     * @return The payload.
     */
    public byte[] getPayload() {
        if (payload == null) {
            payload = new byte[dataSize];
            System.arraycopy(data, dataStartIndex, payload, 0, dataSize);
        }
        return payload;
    }

    /**
     * Sets the payload given the data.
     *
     * @param payload The payload to set to.
     * @throws IllegalArgumentException The payload is null or size does not match {@link #getSize()}.
     */
    public void setPayload(byte[] payload) {
        if (payload == null || payload.length != dataSize)
            throw new IllegalArgumentException("payload null or size does not match");
        this.payload = payload;
        System.arraycopy(payload, 0, data, dataStartIndex, dataSize);
    }

    /**
     * Gets a stream to read the payload.
     *
     * @return The stream.
     */
    public ByteArrayInputStream getPayloadStream() {
        return new ByteArrayInputStream(data, dataStartIndex, dataSize);
    }

    /**
     * Gets a stream to overwrite the payload.
     *
     * @return The stream.
     */
    public ByteBufferOverwriteOutputStream getPayloadWritingStream() {
        return new ByteBufferOverwriteOutputStream(data, dataStartIndex, dataSize);
    }
}
