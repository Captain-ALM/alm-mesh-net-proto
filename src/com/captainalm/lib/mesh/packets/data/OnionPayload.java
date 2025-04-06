package com.captainalm.lib.mesh.packets.data;

import com.captainalm.lib.mesh.packets.Packet;
import com.captainalm.lib.mesh.packets.PacketType;
import com.captainalm.lib.mesh.packets.layer.DataLayer;
import com.captainalm.lib.mesh.packets.layer.OnionLayer;
import com.captainalm.lib.mesh.utils.ByteBufferOverwriteOutputStream;

import java.io.IOException;

/**
 * Encapsulates an {@link OnionLayer}.
 * {@link PacketType#UnicastOnion}
 *
 * @author Alfred Manville
 */
public class OnionPayload extends PacketData {
    protected OnionLayer layer;

    /**
     * Constructs a new instance of OnionPayload with the specified layer.
     *
     * @param layer The onion layer to encapsulate.
     */
    public OnionPayload(OnionLayer layer) {
        super(layer.getSize());
        this.layer = layer;
        ByteBufferOverwriteOutputStream ovrw = new ByteBufferOverwriteOutputStream(data, 0, dataSize);
        try {
            layer.getData().transferTo(ovrw);
        } catch (IOException e) {
        }
    }

    /**
     * Constructs a new instance of OnionPayload from a {@link Packet}.
     *
     * @param packet The packet to construct from.
     */
    public OnionPayload(Packet packet) {
        super(packet);
    }

    /**
     * Gets the {@link OnionLayer}.
     *
     * @return The onion layer.
     */
    public OnionLayer getLayer() {
        if (layer == null) {
            if (data[dataStartIndex] == PacketType.UnicastOnion.getID())
                layer = new OnionLayer(data, dataStartIndex, dataSize);
            else
                layer = new DataLayer(data, dataStartIndex, dataSize);
        }
        return layer;
    }
}
