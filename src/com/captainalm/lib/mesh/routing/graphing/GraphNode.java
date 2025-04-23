package com.captainalm.lib.mesh.routing.graphing;

import com.captainalm.lib.mesh.crypto.IHasher;
import com.captainalm.lib.mesh.transport.INetTransport;
import com.captainalm.lib.mesh.utils.BytesToHex;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Represents a graphing node.
 *
 * @author Alfred Manville
 */
public final class GraphNode {
    public final byte[] ID;
    public final String nodeID;
    public final List<GraphNode> siblings = new CopyOnWriteArrayList<>();
    public final List<GraphNode> etherealNodes = new CopyOnWriteArrayList<>();
    public boolean isGateway;
    private long lastEncryptionKey = 0;
    private byte[] encryptionKey = new byte[32];
    public byte[] kemKey;
    public byte[] dsaKey;
    private byte[] ipv4;
    private byte[] ipv6;
    private String ipv4Str;
    private String ipv6Str;
    public INetTransport transport;
    public final List<String> remoteOnionIDs = new ArrayList<>();
    public final List<String> initOnionIDs = new ArrayList<>();
    public boolean stopEncryptionRequests = false;

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
     * Constructs a new GraphNode given the keys.
     *
     * @param kemKey The ML-KEM Key.
     * @param dsaKey The ML-DSA Key.
     * @param hProvider The hash provider to use.
     * @throws IllegalArgumentException a parameter is null
     */
    public GraphNode(byte[] kemKey, byte[] dsaKey, IHasher hProvider) {
        if (kemKey == null || dsaKey == null || hProvider == null)
            throw new IllegalArgumentException("a parameter is null");
        this.ID = new byte[32];
        System.arraycopy(hProvider.hash(kemKey), 0, this.ID, 0, 16);
        System.arraycopy(hProvider.hash(dsaKey), 0, this.ID, 16, 16);
        this.nodeID = BytesToHex.bytesToHex(this.ID);
        this.kemKey = kemKey;
        this.dsaKey = dsaKey;
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
            if (this.ipv4 == null) {
                this.ipv4 = other.ipv4;
                this.ipv4Str = other.ipv4Str;
            }
            if (this.ipv6 == null) {
                this.ipv6 = other.ipv6;
                this.ipv6Str = other.ipv6Str;
            }
            if (this.dsaKey == null)
                this.dsaKey = other.dsaKey;
            if (this.kemKey == null)
                this.kemKey = other.kemKey;
            if (this.transport == null)
                this.transport = other.transport;
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

    /**
     * Gets the IPv4 Address for this node.
     *
     * @return The IPv4 Address.
     */
    public byte[] getIPv4Address() {
        if (ipv4 == null) {
            ipv4 = new byte[4];
            ipv4[0] = 10;
            System.arraycopy(ID, 0, ipv4, 1, 3);
            ipv4Str = BytesToHex.bytesToHex(ipv4);
        }
        return ipv4;
    }

    /**
     * Gets the IPv6 Address for this node.
     *
     * @return The IPv6 Address.
     */
    public byte[] getIPv6Address() {
        if (ipv6 == null) {
            ipv6 = new byte[16];
            ipv6[0] = (byte) 253;
            ipv6[1] = 10;
            System.arraycopy(ID, ID.length - 14, ipv6, 2, 14);
            ipv6Str = BytesToHex.bytesToHex(ipv6);
        }
        return ipv6;
    }

    /**
     * Gets the IPv4 Address string of the node (In hexadecimal).
     *
     * @return The hexadecimal address.
     */
    public String getIPv4AddressString() {
        if (ipv4Str == null)
            getIPv4Address();
        return ipv4Str;
    }

    /**
     * Gets the IPv6 Address string of the node (In hexadecimal).
     *
     * @return The hexadecimal address.
     */
    public String getIPv6AddressString() {
        if (ipv6Str == null)
            getIPv6Address();
        return ipv6Str;
    }

    /**
     * Gets whether this node owns an ethereal ID.
     *
     * @param eid The ethereal ID to check ownership of.
     * @return If this node is owned.
     */
    public boolean ownsEID(byte[] eid) {
        for (GraphNode etherealNode : etherealNodes)
            if (Arrays.equals(etherealNode.ID, eid))
                return true;
        return false;
    }
}
