package com.captainalm.lib.mesh.packets.data;

import com.captainalm.lib.mesh.packets.Packet;
import com.captainalm.lib.mesh.utils.ByteBufferOverwriteOutputStream;
import com.captainalm.lib.mesh.utils.InputStreamTransfer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Provides the handshake payload for creating a non-endpoint onion circuit.
 * {@link com.captainalm.lib.mesh.packets.PacketType#UnicastOnionCircuitCreate}
 *
 * @author Alfred Manville
 */
public class CircuitCreatePayload extends PacketData implements INonce {
    protected byte[] wrappedKey;

    protected CircuitCreatePayload(int size) {
        super(size);
    }

    /**
     * Constructs a new instance of CircuitCreatePayload with the nonce and specified wrapped key.
     *
     * @param nonce The nonce input stream.
     * @param wrappedKey The wrapped key.
     */
    public CircuitCreatePayload(InputStream nonce, byte[] wrappedKey) {
        super((nonce == null || wrappedKey == null) ? 0 : 16 + wrappedKey.length);
        this.wrappedKey = wrappedKey;
        if (dataSize > 0) {
            try {
                InputStreamTransfer.streamTransfer(nonce, new ByteBufferOverwriteOutputStream(data, 0, 16));
            } catch (IOException ignored) {
            }
            System.arraycopy(wrappedKey, 0, data, 16, wrappedKey.length);
        }
    }

    /**
     * Constructs a new instance of PacketData from a {@link Packet}.
     *
     * @param packet The packet to construct from.
     */
    public CircuitCreatePayload(Packet packet) {
        super(packet);
    }

    /**
     * Gets the nonce in stream form.
     *
     * @return The nonce stream.
     */
    @Override
    public ByteArrayInputStream getNonceStream() {
        return new ByteArrayInputStream(data, dataStartIndex, 16);
    }

    protected int actualKeyLength() {
        return dataSize;
    }

    /**
     * Gets the wrapped key.
     *
     * @return The wrapped key.
     */
    public byte[] getWrappedKey() {
        if (wrappedKey == null && actualKeyLength() > 0) {
            wrappedKey = new byte[actualKeyLength()];
            System.arraycopy(data, dataStartIndex + 16, wrappedKey, 0, actualKeyLength());
        }
        return wrappedKey;
    }
}
