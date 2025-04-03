package com.captainalm.lib.mesh.routing;

import com.captainalm.lib.mesh.crypto.IProvider;
import com.captainalm.lib.mesh.packets.BroadcastPacket;
import com.captainalm.lib.mesh.packets.Packet;
import com.captainalm.lib.mesh.packets.PacketType;
import com.captainalm.lib.mesh.packets.UnicastPacket;
import com.captainalm.lib.mesh.packets.data.SignaturePayload;
import com.captainalm.lib.mesh.packets.data.SinglePayload;
import com.captainalm.lib.mesh.routing.graphing.GraphNode;
import com.captainalm.lib.mesh.transport.INetTransport;
import com.captainalm.lib.mesh.utils.BytesToHex;
import com.captainalm.lib.mesh.utils.StreamEquals;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/**
 * Provides a router class.
 *
 * @author Alfred Manville
 */
public class Router {
    protected final Random random = new Random();

    private final Object packetChargeLock = new Object();
    protected PacketStore freeStore;
    protected PacketStore newestStore;
    protected PacketStore oldestStore;
    protected final Map<String, PacketStore> packetStore = new HashMap<>();
    protected final Map<String, GraphNode> network = new ConcurrentHashMap<>(); // ID to graph node
    protected final Map<String, GraphNode> networkAddresses = new HashMap<>(); // IP Address (Hex) to graph node
    protected final List<GraphNode> gateways = new CopyOnWriteArrayList<>();

    private final List<GraphNode> hopObjects = new ArrayList<>();
    private final Object nextHopLock = new Object();
    private final Map<String, GraphNode> nextHop = new HashMap<>(); // ID to next hop

    protected Map<String, DataLinkProcessor> dataLinks = new ConcurrentHashMap<>(); //ID to data links;
    protected BlockingQueue<BroadcastPacket> receiveQueue = new LinkedBlockingQueue<>();

    protected byte maxTTL;
    protected boolean requireE2E;
    protected boolean ignoreNonE2E;
    protected boolean e2eEnabled;
    protected GraphNode thisNode;
    protected IProvider cryptoProvider;

    protected final Map<String,GraphNode> onionCircuitToInit = new HashMap<>(); //Init OCID to Init Address
    protected final Map<String, byte[]> onionCircuitInitToEncryptionKey = new HashMap<>(); //Init OCID to Encryption Key
    protected final Map<String,String> onionCircuitInitToOnionCircuitRemote = new HashMap<>(); //Init OCID to Remote OCID / Ethereal Address
    protected final Map<String,String> onionCircuitRemoteToOnionCircuitInit = new HashMap<>(); //Remote OCID / Ethereal Address to Init OCID
    protected final Map<String,String> onionCircuitRemoteToRemote = new HashMap<>(); //Remote OCID to Remote Address
    protected final List<byte[]> onionCircuitIDs = new ArrayList<>(); // List of all registered onion circuit IDs
    
    private void hopProcessor(Map<GraphNode,NodeHopInfo> hopInfo,
                              GraphNode thisConnectedTransport, GraphNode currentNode, int currentWeight) {
        // Could have another map registry to mark visited nodes, cleared for each connected transport node
        // to prevent the single double back that occurs on each navigation
        if (!hopInfo.containsKey(currentNode))
            hopInfo.put(currentNode, new NodeHopInfo(thisConnectedTransport, currentWeight));
        for (GraphNode node : currentNode.siblings) {
            if (node == thisNode || thisNode.siblings.contains(node))
                continue;
            NodeHopInfo nodeHopInfo;
            if (hopInfo.containsKey(node) && hopInfo.get(node).currentWeight > currentWeight + 1) {
                nodeHopInfo = hopInfo.get(node);
                nodeHopInfo.currentWeight = currentWeight + 1;
                nodeHopInfo.connectedTransport = thisConnectedTransport;
                hopProcessor(hopInfo, thisConnectedTransport, node, currentWeight + 1);
            } else if (!hopInfo.containsKey(node)) {
                nodeHopInfo = new NodeHopInfo(thisConnectedTransport, currentWeight + 1);
                hopInfo.put(node, nodeHopInfo);
                hopProcessor(hopInfo, thisConnectedTransport, node, currentWeight + 1);
            }
        }
    }

    protected GraphNode[] getNextHops(String address) {
        synchronized (nextHopLock) {
            if (address == null) {
                GraphNode[] nhs = new GraphNode[hopObjects.size()];
                hopObjects.toArray(nhs);
                return nhs;
            } else {
                GraphNode nh = nextHop.get(address);
                if (nh == null) {
                    return new GraphNode[0];
                } else {
                    return new GraphNode[]{nh};
                }
            }
        }
    }

    protected void resetNextHops() {
        synchronized (nextHopLock) {
            nextHop.clear();
            hopObjects.clear();
            hopObjects.addAll(thisNode.siblings);
            Map<GraphNode, NodeHopInfo> hopInfoStore = new HashMap<>();
            for (GraphNode node : hopObjects) {
                hopInfoStore.put(node, new NodeHopInfo(node, 0));
                hopProcessor(hopInfoStore, node, node, 0);
            }
            for (Map.Entry<GraphNode, NodeHopInfo> entry : hopInfoStore.entrySet()) {
                nextHop.put(entry.getKey().nodeID, entry.getValue().connectedTransport);
                for (GraphNode eNode : entry.getKey().etherealNodes)
                    nextHop.put(eNode.nodeID, entry.getValue().connectedTransport);
            }
        };
    }

    private static class NodeHopInfo {
        public GraphNode connectedTransport;
        public int currentWeight;
        public NodeHopInfo(GraphNode connectedTransport, int currentWeight) {
            this.connectedTransport = connectedTransport;
            this.currentWeight = currentWeight;
        }
    }

    /**
     * Receives a packet.
     *
     * @param packet The received packet.
     */
    public void processPacket(Packet packet) {
        if (packet instanceof BroadcastPacket bpk) {
            if (!addressAvailable(BytesToHex.bytesToHex(bpk.getSourceAddress())))
                return;
            if (packet instanceof UnicastPacket upk) {
                if (ownsAddress(upk.getDestinationAddress()))
                    receive(upk);
                else if (packet.getTTL() != 0)
                    route(upk);
            } else {
                if (packet.getTTL() != 0)
                    route(bpk);
                receive(bpk);
            }
        }
    }

    private BroadcastPacket chargePacket(BroadcastPacket toCharge) {
        if (toCharge == null)
            return null;
        PacketStore store;
        byte[] pkHash;
        String pkHashStr;
        SignaturePayload signaturePayload = null;
        if ((toCharge.getType() == PacketType.BroadcastSignature || toCharge.getType() == PacketType.UnicastSignature)
                && toCharge.getPacketData(true) instanceof SignaturePayload sigp) {
            pkHash = sigp.getDataHash().readAllBytes();
            pkHashStr = sigp.getDataHashString();
            signaturePayload = sigp;
        } else {
            pkHash = toCharge.getHash();
            pkHashStr = BytesToHex.bytesToHex(pkHash);
        }
        synchronized (packetChargeLock) {
            store = packetStore.get(pkHashStr);
        }
        if (store == null) {
            synchronized (packetChargeLock) {
                if (freeStore == null) {
                    store = oldestStore;
                    oldestStore = store.newerStore;
                } else {
                    store = freeStore;
                    freeStore = store.nextFreeStore;
                }
                store.newerStore = null;
                store.olderStore = newestStore;
                if (newestStore != null)
                    newestStore.newerStore = store;
                newestStore = store;
                synchronized (store) {
                    store.nextFreeStore = null;
                    store.packetHash = null;
                    packetStore.put(pkHashStr, store);
                }
            }
            synchronized (store) {
                store.packetHash = pkHash;
                if (signaturePayload != null) {
                    store.signatureHash = signaturePayload.getSignatureHash().readAllBytes();
                    store.packetSignature = new SignaturePayload[signaturePayload.getMaxParts()];
                    if (signaturePayload.getPartID() < store.packetSignature.length)
                        store.packetSignature[signaturePayload.getPartID()] = signaturePayload;
                } else {
                    store.signatureHash = null;
                    store.packetSignature = null;
                    store.packet = toCharge;
                }
                store.notifyAll();
            }
        } else {
            synchronized (store) {
                while (store.packetHash == null) {
                    try {
                        store.wait();
                    } catch (InterruptedException e) {
                        return null;
                    }
                }
                if (signaturePayload != null) {
                    if (store.signatureHash == null)
                        store.signatureHash = signaturePayload.getSignatureHash().readAllBytes();
                    else {
                        try {
                            if (!StreamEquals.streamEqualsArray(signaturePayload.getSignatureHash(), store.signatureHash))
                                return null;
                        } catch (IOException e) {
                            return null;
                        }
                    }
                    if (store.packetSignature == null)
                        store.packetSignature = new SignaturePayload[signaturePayload.getMaxParts()];
                    if (signaturePayload.getPartID() < store.packetSignature.length)
                        store.packetSignature[signaturePayload.getPartID()] = signaturePayload;
                } else
                    store.packet = toCharge;
            }
        }
        synchronized (store) {
            Packet toret = null;
            byte[] sig = SignaturePayload.getSignatureFromFragments(store.packetSignature, store.signatureHash, cryptoProvider.GetHasherInstance());
            if (sig.length > 0) {
                if (store.packet.validateWithSignature(cryptoProvider.GetHasherInstance(), cryptoProvider.GetVerifierInstance(), sig))
                    toret = store.packet;
                synchronized (packetChargeLock) {
                    store.olderStore.newerStore = store.newerStore;
                    store.newerStore.olderStore = store.olderStore;
                    store.nextFreeStore = freeStore;
                    freeStore = store;
                    packetStore.remove(pkHashStr);
                }
            }
            return (BroadcastPacket) toret;
        }
    }

    protected void route(BroadcastPacket packet) {
        GraphNode[] dests;
        if (packet instanceof UnicastPacket upk)
            dests = getNextHops(BytesToHex.bytesToHex(upk.getDestinationAddress()));
        else
            dests = getNextHops(null);
        for (GraphNode node : dests) {
            if (node.transport != null)
                node.transport.send(packet.getPacketBytes());
        }
    }

    public void send(BroadcastPacket packet) {
        byte[] key = null;
        PacketType pt = packet.getType();
        if (pt != PacketType.UnicastSignature && pt != PacketType.UnicastEncryptionRejectedHandshake &&
                pt != PacketType.UnicastEncryptionRequestHandshake &&
                pt != PacketType.UnicastEncryptionResponseHandshake &&
                pt != PacketType.UnicastOnionCircuitCreate && pt != PacketType.UnicastOnionCircuitBroken &&
                pt != PacketType.UnicastOnionCircuitCreateEndpoint && pt != PacketType.UnicastOnionCircuitCreated &&
                pt != PacketType.UnicastOnionCircuitRejected) { // Packet type not a handshake (Handshake encryption not allowed)
            if (packet instanceof UnicastPacket upk) {
                GraphNode dest = network.get(BytesToHex.bytesToHex(upk.getDestinationAddress()));
                if (dest != null) {
                    key = dest.getEncryptionKey();
                    if (key == null && e2eEnabled && requireE2E)
                        key = sendEncryptionHandshake(dest);
                }
            }
        }
        try {
            if (key != null)
                packet.Encrypt(cryptoProvider.GetCryptorInstance().setKey(key));
            packet.calculateHash(cryptoProvider.GetHasherInstance());
            Packet[] sigp = packet.getSignaturePackets(cryptoProvider.GetHasherInstance(), cryptoProvider.GetSignerInstance().setPrivateKey(thisNode.dsaKey), 1210);
            for (Packet p : sigp) {
                p.calculateHash(cryptoProvider.GetHasherInstance());
                route((BroadcastPacket) p);
            }
            route(packet);
        } catch (GeneralSecurityException e) {
        }
    }

    private byte[] sendEncryptionHandshake(GraphNode target) {
        byte[] key = new byte[32];
        random.nextBytes(key);
        try {
            SinglePayload enchp = new SinglePayload(cryptoProvider.GetWrapperInstance().setPublicKey(target.kemKey).wrap(key));
            target.setEncryptionKey(key, Instant.now().getEpochSecond());
            send((BroadcastPacket) new UnicastPacket(enchp.getSize()).setDestinationAddress(target.ID)
                    .setSourceAddress(thisNode.ID).setTTL(maxTTL).setPacketType(PacketType.UnicastEncryptionRequestHandshake).setPacketData(enchp));
            return key;
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    public void receive(BroadcastPacket packet) {
        packet = chargePacket(packet);
        if (packet != null) {
            GraphNode sour = network.get(BytesToHex.bytesToHex(packet.getSourceAddress()));
            if (packet.isEncrypted() && e2eEnabled) {
                if (sour != null) {
                    byte[] key = sour.getEncryptionKey();
                    if (key != null) {
                        try {
                            packet.Decrypt(cryptoProvider.GetCryptorInstance());
                        } catch (GeneralSecurityException e) {
                            return;
                        }
                    }
                }
            } else if (e2eEnabled && requireE2E) {
                sendEncryptionHandshake(sour);
                if (ignoreNonE2E)
                    return;
            }
            receiveQueue.add(packet);
        }
    }

    public byte[] getNodeID(String addressIP) {
        GraphNode n = networkAddresses.get(addressIP);
        if (n == null)
            return null;
        return n.ID;
    }

    public byte[] getThisNodeID() {
        return thisNode.ID;
    }

    public byte[] getGatewayNodeID() {
        GraphNode n = null;
        for (GraphNode node : gateways) {
            n = node;
            break;
        }
        if (n == null)
            return null;
        return n.ID;
    }

    protected boolean ownsAddress(byte[] address) {
        return Arrays.equals(address, thisNode.ID) || thisNode.ownsEID(address);
    }

    protected boolean addressAvailable(String address) {
        return getNextHops(address).length > 0;
    }

    /**
     * Embedded class representing an active data link.
     *
     * @author Alfred Manville
     */
    protected class DataLinkProcessor implements Runnable {
        public final INetTransport dataLink;
        public final Thread recvThread = new Thread(this);
        public final GraphNode linkedNode;

        public DataLinkProcessor(INetTransport dataLink, GraphNode linkedNode) {
            this.dataLink = dataLink;
            this.linkedNode = linkedNode;
            linkedNode.transport = dataLink;
        }

        @Override
        public void run() {
            while(dataLink.isActive()) {
                byte[] data = dataLink.receive();
                if (data == null)
                    return;
                Packet pk = Packet.getPacketFromBytes(data);
                if (pk.getType() == PacketType.Unknown || !pk.verifyHash(cryptoProvider.GetHasherInstance()))
                    continue;
                pk.decrementTTL();
                processPacket(pk);
            }
        }
    }
}
