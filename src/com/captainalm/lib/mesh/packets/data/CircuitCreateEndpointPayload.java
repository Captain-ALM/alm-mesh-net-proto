package com.captainalm.lib.mesh.packets.data;

import com.captainalm.lib.mesh.packets.Packet;
import com.captainalm.lib.mesh.utils.ByteBufferOverwriteOutputStream;

import java.io.IOException;
import java.io.InputStream;

/**
 * Provides the handshake payload for creating an endpoint onion circuit.
 * {@link com.captainalm.lib.mesh.packets.PacketType#UnicastOnionCircuitCreateEndpoint}
 *
 * @author Alfred Manville
 */
public class CircuitCreateEndpointPayload extends CircuitCreatePayload {
    protected byte[] etherealNodeID;

    /**
     * Constructs a new instance of PacketData from a {@link Packet}.
     *
     * @param packet The packet to construct from.
     */
    public CircuitCreateEndpointPayload(Packet packet) {
        super(packet);
    }

    /**
     * Constructs a new instance of CircuitCreatePayload with the nonce,
     * specified wrapped key and ethereal node ID..
     *
     * @param nonce      The nonce input stream.
     * @param wrappedKey The wrapped key.
     * @param etherealNodeID The ethereal node ID.
     */
    public CircuitCreateEndpointPayload(InputStream nonce, byte[] wrappedKey, byte[] etherealNodeID) {
        super((nonce == null || wrappedKey == null || etherealNodeID == null || etherealNodeID.length != 32) ? 0 : 48 + wrappedKey.length);
        this.etherealNodeID = etherealNodeID;
        this.wrappedKey = wrappedKey;
        if (dataSize > 0) {
            try {
                nonce.transferTo(new ByteBufferOverwriteOutputStream(data, 0, 16));
            } catch (IOException ignored) {
            }
            System.arraycopy(wrappedKey, 0, data, 16, wrappedKey.length);
            System.arraycopy(etherealNodeID, 0, data, 16 + wrappedKey.length, 32);
        }
    }

    @Override
    protected int actualKeyLength() {
        return super.actualKeyLength() - 32;
    }

    /**
     * Gets the ethereal node ID.
     *
     * @return The ethereal node ID.
     */
    public byte[] getEtherealNodeID() {
        if (etherealNodeID == null && dataSize > 47) {
            etherealNodeID = new byte[32];
            System.arraycopy(data, dataSize - 32 + dataStartIndex, etherealNodeID, 0, 32);
        }
        return etherealNodeID;
    }
}
