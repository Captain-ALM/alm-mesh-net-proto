package com.captainalm.lib.mesh.packets.data;

import com.captainalm.lib.mesh.packets.Packet;
import com.captainalm.lib.mesh.routing.graphing.GraphNode;
import com.captainalm.lib.mesh.utils.BytesToHex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Provides the ability to send a list of gateways.
 * {@link com.captainalm.lib.mesh.packets.PacketType#BroadcastGateway}
 *
 * @author Alfred Manville
 */
public class GatewayPayload extends PacketData {
    protected List<String> gateways;

    /**
     * Constructs a new instance of GatewayPayload from a {@link Packet}.
     *
     * @param packet The packet to construct from.
     */
    public GatewayPayload(Packet packet) {
        super(packet);
    }

    /**
     * Constructs a new instance of GatewayPayload from a list of gateway nodes.
     *
     * @param gateways A collection of gateway nodes.
     */
    public GatewayPayload(List<GraphNode> gateways) {
        super(32 * gateways.size());
        this.gateways = new ArrayList<>(gateways.size());
        int pos = 0;
        for (GraphNode node : gateways) {
            this.gateways.add(node.nodeID);
            System.arraycopy(node.ID, 0, data, pos, 32);
            pos += 32;
        }
    }

    /**
     * Gets a list of gateways stored in this packet.
     * Modifying does nothing to the underlying data.
     *
     * @return A list of gateway IDs.
     */
    public List<String> getGateways() {
        if (gateways == null) {
            int cap = dataSize/32;
            gateways = new ArrayList<>(cap);
            ByteArrayInputStream din = new ByteArrayInputStream(data, dataStartIndex, dataSize);
            for (int i = 0; i < cap; i++) {
                try {
                    gateways.add(BytesToHex.bytesToHexFromStreamWithSize(din, 32));
                } catch (IOException ignored) {
                }
            }
        }
        return gateways;
    }

    /**
     * Gets the gateways, adding / updating a network map if applicable and gateway list.
     *
     * @param network The network of graph nodes.
     * @param gateways The list of gateways.
     * @param addressToGraphNode The network nodes to addresses.
     */
    public void getGateways(Map<String, GraphNode> network , List<GraphNode> gateways, Map<String, GraphNode> addressToGraphNode) {
        if (getGateways() != null && network != null && gateways != null) {
            for (String gatewayID : getGateways()) {
                GraphNode gateway = network.get(gatewayID);
                if (gateway == null) {
                    gateway = new GraphNode(BytesToHex.hexToBytes(gatewayID));
                    gateway.isGateway = true;
                    network.put(gatewayID, gateway);
                    addressToGraphNode.put(gateway.getIPv4AddressString(), gateway);
                    addressToGraphNode.put(gateway.getIPv6AddressString(), gateway);
                }
                if (!gateways.contains(gateway))
                    gateways.add(gateway);
            }
        }
    }
}
