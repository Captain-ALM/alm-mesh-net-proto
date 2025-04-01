package com.captainalm.lib.mesh.routing.graphing;

import com.captainalm.lib.mesh.utils.BytesToHex;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

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
}
