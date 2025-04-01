package com.captainalm.lib.mesh.packets.data;

import com.captainalm.lib.mesh.packets.Packet;
import com.captainalm.lib.mesh.routing.graphing.GraphNode;
import com.captainalm.lib.mesh.utils.BytesToHex;

import java.util.Map;

/**
 * Provides the ability to associate a list of nodes with a node.
 * For {@link GraphNode}
 * {@link com.captainalm.lib.mesh.packets.PacketType#DirectGraphing}
 * {@link com.captainalm.lib.mesh.packets.PacketType#BroadcastGraphing}
 * {@link com.captainalm.lib.mesh.packets.PacketType#DirectNodesEID}
 *
 * @author Alfred Manville
 */
public class NodeAssociationPayload extends PacketData {
    GraphNode node;
    boolean isSiblings;

    /**
     * Constructs a new instance of NodeAssociationPayload from a {@link Packet}.
     *
     * @param packet The packet to construct from.
     * @param isSiblings If the packet is for graphing and not {@link com.captainalm.lib.mesh.packets.PacketType#DirectNodesEID}
     */
    public NodeAssociationPayload(Packet packet, boolean isSiblings) {
        super(packet);
        this.isSiblings = isSiblings;
    }

    /**
     * Constructs a new instance of NodeAssociationPayload for the specified {@link GraphNode}.
     *
     * @param node The node to store.
     * @param isSiblings store the siblings and not the etherealNodes.
     */
    public NodeAssociationPayload(GraphNode node, boolean isSiblings) {
        super((node == null) ? 0 : 32 + ((isSiblings ? 32 * node.siblings.size() : 32 * node.etherealNodes.size())));
        this.node = node;
        this.isSiblings = isSiblings;
        if (node != null) {
            System.arraycopy(node.ID, 0, data, 0, 32);
            int pos = 32;
            if (isSiblings) {
                for (GraphNode sibling : node.siblings) {
                    System.arraycopy(sibling.ID, 0, data, pos, 32);
                    pos += 32;
                }
            } else {
                for (GraphNode eNode : node.etherealNodes) {
                    System.arraycopy(eNode.ID, 0, data, pos, 32);
                    pos += 32;
                }
            }
        }
    }

    /**
     * Gets the {@link GraphNode} object, using existing instances
     * and adding new ones if needed to a map.
     *
     * @param graphNodes A map of existing graph nodes.
     * @return The graph node.
     */
    public GraphNode getNode(Map<String,GraphNode> graphNodes) {
        if (node == null && graphNodes != null) {
            byte[] thisNode = new byte[32];
            System.arraycopy(data, dataStartIndex, thisNode, 0, 32);
            String thisNodeStr = BytesToHex.bytesToHex(thisNode);
            if (graphNodes.containsKey(thisNodeStr)) {
                node = graphNodes.get(thisNodeStr);
            } else {
                node = new GraphNode(thisNode);
                graphNodes.put(thisNodeStr, node);
            }
            for (int pos = dataStartIndex + 32; pos < dataStartIndex + dataSize; pos+= 32) {
                byte[] cNode = new byte[32];
                System.arraycopy(data, pos, cNode, 0, 32);
                String cNodeStr = BytesToHex.bytesToHex(cNode);
                GraphNode cNodeO;
                if (graphNodes.containsKey(cNodeStr)) {
                    cNodeO = graphNodes.get(cNodeStr);
                } else {
                    cNodeO = new GraphNode(cNode);
                    graphNodes.put(cNodeStr, cNodeO);
                }
                if (isSiblings)
                    node.combineSibling(cNodeO);
                else
                    node.combineEthereal(cNodeO);
            }
        }
        return node;
    }
}
