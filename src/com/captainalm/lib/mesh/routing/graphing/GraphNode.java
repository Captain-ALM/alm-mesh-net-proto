package com.captainalm.lib.mesh.routing.graphing;

import com.captainalm.lib.mesh.utils.BytesToHex;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * Represents a graphing node.
 *
 * @author Alfred Manville
 */
public final class GraphNode {
    public final byte[] ID;
    public final String nodeID;
    public final List<GraphNode> siblings = new LinkedList<>();
    public final List<GraphNode> etherealNodes = new LinkedList<>();
    public boolean isGateway;
    private long lastEncryptionKey = 0;
    private byte[] encryptionKey = new byte[32];

    /**
     * Constructs a new GraphNode.
     *
     * @param ID The ID of the node.
     */
    public GraphNode(byte[] ID) {
        this.ID = ID;
        this.nodeID = BytesToHex.bytesToHex(ID);
    }

    /**
     * Combines a GraphNode object with this one.
     *
     * @param other The other graph node object.
     */
    public void combine(GraphNode other) {
        if (other != null && Arrays.equals(this.ID, other.ID))
            for (GraphNode sibling : other.siblings) {
                if (!this.siblings.contains(sibling))
                    this.siblings.add(sibling);
            for (GraphNode etherealNode : other.etherealNodes)
                if (!this.etherealNodes.contains(etherealNode))
                    this.etherealNodes.add(etherealNode);
            setEncryptionKey(other.encryptionKey, other.lastEncryptionKey);
        }
    }

    /**
     * Adds a non-existent sibling node.
     *
     * @param sibling The sibling to add.
     */
    public void combineSibling(GraphNode sibling) {
        if (!this.siblings.contains(sibling))
            this.siblings.add(sibling);
    }

    /**
     * Adds a non-existent ethereal node.
     *
     * @param etherealNode The ethereal node to add.
     */
    public void combineEthereal(GraphNode etherealNode) {
        if (!this.etherealNodes.contains(etherealNode))
            this.etherealNodes.add(etherealNode);
    }

    /**
     * Gets the E2E encryption key.
     *
     * @return The E2E encryption key.
     */
    public byte[] getEncryptionKey() {
        return encryptionKey;
    }

    /**
     * Sets the encryption key (If timestamp is younger).
     *
     * @param encryptionKey The encryption key.
     * @param timestamp The timestamp.
     */
    public void setEncryptionKey(byte[] encryptionKey, long timestamp) {
        if (timestamp < lastEncryptionKey || encryptionKey == null || encryptionKey.length != 32)
            return;
        lastEncryptionKey = timestamp;
        this.encryptionKey = encryptionKey;
    }
}
