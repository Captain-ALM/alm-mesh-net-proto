package com.captainalm.lib.mesh.routing;

import com.captainalm.lib.mesh.crypto.IProvider;
import com.captainalm.lib.mesh.handshake.HandshakeProcessor;
import com.captainalm.lib.mesh.packets.*;
import com.captainalm.lib.mesh.packets.data.*;
import com.captainalm.lib.mesh.packets.layer.DataLayer;
import com.captainalm.lib.mesh.packets.layer.OnionLayer;
import com.captainalm.lib.mesh.routing.graphing.GraphNode;
import com.captainalm.lib.mesh.transport.INetTransport;
import com.captainalm.lib.mesh.utils.BytesToHex;
import com.captainalm.lib.mesh.utils.StreamEquals;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/**
 * Provides a router class.
 *
 * @author Alfred Manville
 */
public class Router {
    protected final Random random = new SecureRandom();
    protected final IPacketProcessor pkProcessor;
    protected boolean active;

    private final Object packetChargeLock = new Object();
    protected PacketStore freeStore;
    protected PacketStore newestStore;
    protected PacketStore oldestStore;
    protected final Map<String, PacketStore> packetStore = new HashMap<>();
    protected final Map<String, GraphNode> network = new ConcurrentHashMap<>(); // ID to graph node
    protected final Map<String, GraphNode> networkAddresses = new ConcurrentHashMap<>(); // IP Address (Hex) to graph node
    protected final List<GraphNode> gateways = new CopyOnWriteArrayList<>();

    private final List<GraphNode> hopObjects = new ArrayList<>();
    private final Object nextHopLock = new Object();
    private final Map<String, GraphNode> nextHop = new HashMap<>(); // ID to next hop
    private final byte[] kemPrivateKey;
    private final byte[] dsaPrivateKey;

    private final BlockingQueue<Exception> errors = new LinkedBlockingQueue<>();
    private final BlockingQueue<NodeUpdate> updates = new LinkedBlockingQueue<>();

    protected final Map<String, DataLinkProcessor> dataLinks = new ConcurrentHashMap<>(); //ID to data links;
    protected final List<DataLinkProcessor> dataLinkList = new CopyOnWriteArrayList<>();
    protected final BlockingQueue<Packet> receiveQueue = new LinkedBlockingQueue<>();
    protected final Thread receiveThread = new Thread(() -> {
        try {
            while (active) {
                try {
                    protectedReceive(receiveQueue.take());
                } catch (InterruptedException ignored) {
                }
            }
        } catch (RuntimeException e) {
            errors.add(e);
        }
    });

    protected byte maxTTL;
    protected boolean requireE2E;
    protected boolean ignoreNonE2E;
    protected boolean e2eEnabled;
    protected final GraphNode thisNode;
    protected final IProvider cryptoProvider;

    protected final Map<String, byte[]> onionCircuitInitToEncryptionKey = new HashMap<>(); //Init OCID to Encryption Key

    protected final Map<String,String> onionCircuitInitToOnionCircuitRemote = new HashMap<>(); //Init OCID to Remote OCID / Ethereal Address
    protected final Map<String,String> onionCircuitRemoteToOnionCircuitInit = new HashMap<>(); //Remote OCID / Ethereal Address to Init OCID

    protected final Map<String,GraphNode> onionCircuitInitToInit = new HashMap<>(); //Init OCID to Init Node

    protected final Map<String,GraphNode> onionCircuitRemoteToRemote = new HashMap<>(); //Remote OCID to Remote Node

    protected final Map<String, String> nIDtoOnionCircuitID = new HashMap<>(); // N ID to Onion circuit ID
    protected final Map<String,GraphNode> etherealNodeToOwner = new HashMap<>();

    private final Object lockOnionCircuitIDs = new Object();
    protected final List<String> onionCircuitIDs = new ArrayList<>(); // List of all registered onion circuit IDs
    private final Object locknIDs = new Object();
    protected final List<String> nIDs = new ArrayList<>();

    /**
     * Constructs a new router with the specified node information, private keys, cryptographic provider and packet processor.
     *
     * @param local The local node information.
     * @param privateKEMKey The private ML-KEM key for this node.
     * @param privateDSAKey The private ML-DSA key for this node.
     * @param cryptographicProvider The cryptographic provider.
     * @param packetProcessor The {@link IPacketProcessor} for this router.
     * @param packetChargeCount The number of packets to cache (Minimum 4).
     * @param maxTTL The maximum TTL of the packets from 1-254.
     * @param e2eEnabled Enable end to end encryption.
     * @param requireE2E Require end to end encryption.
     * @param ignoreNonE2E Ignore non E2E received packets.
     * @throws IllegalArgumentException Objects passed are null or inconsistent with limits.
     */
    public Router(GraphNode local, byte[] privateKEMKey, byte[] privateDSAKey, IProvider cryptographicProvider, IPacketProcessor packetProcessor,
                  long packetChargeCount, byte maxTTL, boolean e2eEnabled, boolean requireE2E, boolean ignoreNonE2E) {
        if (local == null || privateKEMKey == null || privateDSAKey == null || cryptographicProvider == null || packetProcessor == null)
            throw new IllegalArgumentException("parameter cannot be null");
        thisNode = local;
        kemPrivateKey = privateKEMKey;
        dsaPrivateKey = privateDSAKey;
        cryptoProvider = cryptographicProvider;
        pkProcessor = packetProcessor;
        network.put(local.nodeID, local);
        networkAddresses.put(local.getIPv4AddressString(), local);
        networkAddresses.put(local.getIPv6AddressString(), local);
        if (maxTTL == (byte) 255 || maxTTL == 0)
            throw new IllegalArgumentException("maxTTL must not be infinite nor 0");
        this.maxTTL = maxTTL;
        this.e2eEnabled = e2eEnabled;
        if (requireE2E && !e2eEnabled)
            throw new IllegalArgumentException("requiring e2e requires enablement");
        this.requireE2E = requireE2E;
        if (ignoreNonE2E && !e2eEnabled)
            throw new IllegalArgumentException("ignoring non e2e requires enablement and requiring e2e");
        this.ignoreNonE2E = ignoreNonE2E;
        if (packetChargeCount < 4)
            throw new IllegalArgumentException("packet charge count must be at least 4");
        freeStore = new PacketStore();
        PacketStore cStore = freeStore;
        for (int i =1; i < packetChargeCount; i++) {
            cStore.nextFreeStore = new PacketStore();
            cStore = cStore.nextFreeStore;;
        }
        active = true;
        receiveThread.setDaemon(true);
        receiveThread.start();
    }

    /**
     * Adds a handshaked transport to this router.
     *
     * @param transport The transport to add.
     * @param extraPackets The extra packets from {@link HandshakeProcessor#getOtherPackets()}.
     */
    public void addTransport(GraphNode node, INetTransport transport, List<Packet> extraPackets) {
        if (node == null || transport == null || extraPackets == null)
            return;
        GraphNode existing = network.get(node.nodeID);
        if (existing == null) {
            existing = node;
            network.put(node.nodeID, existing);
            networkAddresses.put(node.getIPv4AddressString(), node);
            networkAddresses.put(node.getIPv6AddressString(), node);
            updates.add(new NodeUpdate(node, false));
            resetNextHops();
        } else
            existing.combine(node);
        if (!dataLinks.containsKey(existing.nodeID)) {
            DataLinkProcessor p = new DataLinkProcessor(transport, existing);
            dataLinks.put(existing.nodeID, p.start());
            dataLinkList.add(p);
        }
    }

    /**
     * Checks if the router is active.
     *
     * @return If the router is active.
     */
    public boolean isActive() {
        return active;
    }

    /**
     * Deactivate the router.
     *
     * @param shutdownTransports If the attached transports should be closed.
     */
    public void deactivate(boolean shutdownTransports) {
        active = false;
        pkProcessor.terminate();
        receiveThread.interrupt();
        if (shutdownTransports) {
            for (DataLinkProcessor processor : dataLinkList)
                processor.dataLink.close();
        }
    }

    protected void protectedReceive(Packet packet) {
        PacketType pt = packet.getType();
        if (pt.getMessagingType() != PacketMessagingType.Unicast)
            processBroadcast(packet);
        else if (packet instanceof UnicastPacket upk) {
            if (thisNode.ownsEID(upk.getDestinationAddress()))
                processEthereal(upk);
            else {
                try {
                    if (pt == PacketType.UnicastEncryptionRequestHandshake && packet.getPacketData(true) instanceof SinglePayload sp) {
                        GraphNode erNode = network.get(BytesToHex.bytesToHex(upk.getSourceAddress()));
                        if (erNode != null) {
                            try {
                                byte[] dKey = cryptoProvider.GetUnwrapperInstance().setPrivateKey(kemPrivateKey).unwrap(sp.getPayload());
                                if (dKey != null) {
                                    erNode.setEncryptionKey(dKey, packet.getTimeStamp());
                                    updates.add(new NodeUpdate(erNode, false));
                                    SinglePayload spts = new SinglePayload(cryptoProvider.GetCryptorInstance().setKey(erNode.getEncryptionKey())
                                            .encrypt(erNode.getEncryptionKey()));
                                    send((BroadcastPacket) new UnicastPacket(spts.getSize()).setDestinationAddress(upk.getSourceAddress())
                                            .setSourceAddress(thisNode.ID).setTTL(maxTTL).setPacketType(PacketType.UnicastEncryptionResponseHandshake)
                                            .setPacketData(spts).timeStamp());
                                } else
                                    throw new GeneralSecurityException();
                            } catch (GeneralSecurityException e) {
                                errors.add(e);
                                send((BroadcastPacket) new UnicastPacket(0).setDestinationAddress(upk.getSourceAddress())
                                        .setSourceAddress(thisNode.ID).setTTL(maxTTL).setPacketType(PacketType.UnicastEncryptionRejectedHandshake)
                                        .timeStamp());
                            }
                        }
                    } else if (pt == PacketType.UnicastEncryptionResponseHandshake && packet.getPacketData(true) instanceof SinglePayload sp) {
                        GraphNode erNode = network.get(BytesToHex.bytesToHex(upk.getSourceAddress()));
                        if (erNode != null) {
                            try {
                                byte[] dKey = cryptoProvider.GetCryptorInstance().setKey(erNode.getEncryptionKey()).decrypt(sp.getPayload());
                                if (dKey != null) {
                                    erNode.setEncryptionKey(dKey, packet.getTimeStamp());
                                    updates.add(new NodeUpdate(erNode, false));
                                }
                            } catch (GeneralSecurityException e) {
                                errors.add(e);
                            }
                        }
                    } else if (pt == PacketType.UnicastEncryptionRejectedHandshake) {
                        GraphNode erNode = network.get(BytesToHex.bytesToHex(upk.getSourceAddress()));
                        if (erNode != null)
                            erNode.stopEncryptionRequests = true;
                    } else if (pt == PacketType.UnicastOnionCircuitCreated && packet.getPacketData(true) instanceof CircuitCreatedPayload ocp
                    && !nIDtoOnionCircuitID.containsKey(BytesToHex.bytesToHexFromStreamWithSize(ocp.getNonceStream(), 16)))
                        pkProcessor.processPacket(packet);
                    else if (pt == PacketType.UnicastOnionCircuitRejected && packet.getPacketData(true) instanceof SinglePayload sp
                    && !nIDtoOnionCircuitID.containsKey(BytesToHex.bytesToHexFromStreamWithSize(sp.getPayloadStream(), 16)))
                        pkProcessor.processPacket(packet);
                    else if (pt == PacketType.UnicastOnionCircuitBroken || pt == PacketType.UnicastOnion) {
                        processOnion(upk);
                        pkProcessor.processPacket(packet);
                    }
                    else if (pt == PacketType.UnicastOnionCircuitCreated || pt == PacketType.UnicastOnionCircuitCreate ||
                    pt == PacketType.UnicastOnionCircuitCreateEndpoint ||
                    pt == PacketType.UnicastOnionCircuitRejected)
                        processOnion(upk);
                    else
                        pkProcessor.processPacket(packet);
                } catch (IOException e) {
                    errors.add(e);
                }
            }
        }
    }

    protected void processBroadcast(Packet packet) {
        if (packet instanceof BroadcastPacket bpk)
            for (GraphNode eNode : thisNode.etherealNodes)
                processEtherealNode(bpk, eNode);
        PacketData payload = packet.getPacketData(true);
        if (payload instanceof AssociatedPayload adp) {
            switch (packet.getType()) {
                case BroadcastAssociateEID -> {
                    GraphNode owner = network.get(BytesToHex.bytesToHex(adp.getAssociatedPayload()));
                    if (owner != null)
                        registerEtherealNode(new GraphNode(adp.getAssociateID()), owner);
                }
                case BroadcastAssociateKEMKey, BroadcastAssociateDSAKey -> {
                    GraphNode owner = network.get(BytesToHex.bytesToHex(adp.getAssociateID()));
                    if (owner != null)
                        if (packet.getType() == PacketType.BroadcastAssociateKEMKey)
                            owner.kemKey = adp.getAssociatedPayload();
                        else
                            owner.dsaKey = adp.getAssociatedPayload();
                }
            }
        } else if (payload instanceof AssociatePayload ap) {
            switch (packet.getType()) {
                case BroadcastDeAssociateEID, BroadcastNodeDead -> removeNode(network.get(BytesToHex.bytesToHex(ap.getAssociateID())));
            }
        } else if (payload instanceof NodeAssociationPayload nap) {
            switch (packet.getType()) {
                case DirectGraphing:
                    send((BroadcastPacket) new BroadcastPacket(nap.getSize()).setSourceAddress(thisNode.ID)
                            .setPacketData(nap).setPacketType(PacketType.BroadcastGraphing).setTTL(maxTTL)
                            .timeStamp());
                case BroadcastGraphing, DirectNodesEID:
                    GraphNode tcNode = nap.getNode(network, networkAddresses);
                    if (tcNode != null) {
                        updates.add(new NodeUpdate(tcNode, false));
                        resetNextHops();
                        if (packet.getType() == PacketType.DirectNodesEID) {
                            AssociatedPayload bPayload;
                            for (GraphNode eNode : tcNode.etherealNodes) {
                                bPayload = new AssociatedPayload(eNode.ID, tcNode.ID);
                                send((BroadcastPacket) new BroadcastPacket(bPayload.getSize()).setSourceAddress(thisNode.ID).setTTL(maxTTL)
                                        .setPacketType(PacketType.BroadcastAssociateEID).setPacketData(bPayload).timeStamp());
                            }
                        }
                    }
                    break;
            }
        } else if (payload instanceof GatewayPayload gp &&
        packet.getType() == PacketType.BroadcastGateway)
            gp.getGateways(network, gateways, networkAddresses);
    }

    private void registerEtherealNode(GraphNode node, GraphNode owner) {
        owner.etherealNodes.add(node);
        etherealNodeToOwner.put(node.nodeID, owner)
;       network.put(node.nodeID, node);
        networkAddresses.put(owner.getIPv4AddressString(), node);
        networkAddresses.put(owner.getIPv6AddressString(), node);
        updates.add(new NodeUpdate(node, false));
        resetNextHops();
    }

    private void removeNode(GraphNode node) {
        GraphNode owner = etherealNodeToOwner.get(node.nodeID);
        if (owner != null) {
            owner.etherealNodes.remove(node);
            etherealNodeToOwner.remove(node.nodeID);
        }
        if (!node.etherealNodes.isEmpty())
            for (GraphNode eNode : node.etherealNodes)
                removeNode(eNode);
        network.remove(node.nodeID);
        networkAddresses.remove(node.getIPv4AddressString());
        networkAddresses.remove(node.getIPv6AddressString());
        updates.add(new NodeUpdate(node, true));
        if (node.isGateway)
            gateways.remove(node);
        String[] localOIDs = new String[0];
        localOIDs = node.initOnionIDs.toArray(localOIDs);
        for (String oid : localOIDs)
            deleteCircuit(BytesToHex.hexToBytes(oid));
        localOIDs = node.remoteOnionIDs.toArray(new String[0]);
        for (String oid : localOIDs)
            deleteCircuit(BytesToHex.hexToBytes(oid));
        resetNextHops();
    }

    protected void deleteCircuit(byte[] circuitID) {
        // Broadcast circuit broken in both 'directions'
        String strCID = BytesToHex.bytesToHex(circuitID);
        BroadcastPacket toSend = null;
        PacketData sendPayload = null;
        BroadcastPacket toSend2 = null;
        PacketData sendPayload2 = null;
        if (onionCircuitInitToOnionCircuitRemote.containsKey(strCID)) { // Owns this circuit
            String ocr = onionCircuitInitToOnionCircuitRemote.get(strCID);
            onionCircuitInitToOnionCircuitRemote.remove(strCID);
            if (ocr != null)
                onionCircuitRemoteToOnionCircuitInit.remove(ocr);
            GraphNode initNode = onionCircuitInitToInit.remove(strCID);
            GraphNode remoteNode;
            if (initNode != null) {
                initNode.initOnionIDs.remove(strCID);
                onionCircuitInitToEncryptionKey.remove(strCID);
                sendPayload = new SinglePayload(circuitID);
                toSend = (BroadcastPacket) new UnicastPacket(sendPayload.getSize()).setDestinationAddress(initNode.ID)
                        .setSourceAddress(thisNode.ID).setTTL(maxTTL).setPacketType(PacketType.UnicastOnionCircuitBroken);
            }
            removeCircuitID(circuitID);
            if (ocr != null && ocr.length() == 64) { // Endpoint circuit
                GraphNode eNode = network.get(ocr);
                if (eNode != null) {
                    sendPayload2 = new AssociatePayload(eNode.ID);
                    toSend2 = (BroadcastPacket) new BroadcastPacket(sendPayload2.getSize()).setSourceAddress(thisNode.ID)
                            .setTTL(maxTTL).setPacketType(PacketType.BroadcastDeAssociateEID);
                    removeNode(eNode);
                }
            } else if (ocr != null) { // Forward circuit
                sendPayload = new SinglePayload(circuitID);
                remoteNode = onionCircuitRemoteToRemote.remove(ocr);
                if (remoteNode != null) {
                    remoteNode.remoteOnionIDs.remove(ocr);
                    sendPayload2 = new SinglePayload(BytesToHex.hexToBytes(ocr));
                    toSend2 = (BroadcastPacket) new UnicastPacket(sendPayload2.getSize()).setDestinationAddress(remoteNode.ID)
                            .setSourceAddress(thisNode.ID).setTTL(maxTTL).setPacketType(PacketType.UnicastOnionCircuitBroken);
                }
                removeCircuitIDString(ocr);

            }
        } else if (onionCircuitRemoteToOnionCircuitInit.containsKey(strCID) && circuitID.length == 16) { // Attached to this circuit
            String oci = onionCircuitRemoteToOnionCircuitInit.get(strCID);
            onionCircuitRemoteToOnionCircuitInit.remove(strCID);
            if (oci != null && oci.length() == 32) { // Forward circuit
                onionCircuitInitToOnionCircuitRemote.remove(oci);
                GraphNode remoteNode = onionCircuitRemoteToRemote.remove(strCID);
                if (remoteNode != null) {
                    remoteNode.remoteOnionIDs.remove(strCID);
                    sendPayload = new SinglePayload(circuitID);
                    toSend = (BroadcastPacket) new UnicastPacket(sendPayload.getSize()).setDestinationAddress(remoteNode.ID)
                            .setSourceAddress(thisNode.ID).setTTL(maxTTL).setPacketType(PacketType.UnicastOnionCircuitBroken);
                }
                removeCircuitID(circuitID);
                GraphNode initNode = onionCircuitInitToInit.remove(strCID);
                if (initNode != null) {
                    initNode.initOnionIDs.remove(oci);
                    onionCircuitInitToEncryptionKey.remove(oci);
                    sendPayload2 = new SinglePayload(BytesToHex.hexToBytes(oci));
                    toSend2 = (BroadcastPacket) new UnicastPacket(sendPayload2.getSize()).setDestinationAddress(initNode.ID)
                            .setSourceAddress(thisNode.ID).setTTL(maxTTL).setPacketType(PacketType.UnicastOnionCircuitBroken);
                }
                removeCircuitIDString(oci);
            }
        }
        if (toSend != null)
            send((BroadcastPacket) toSend.setPacketData(sendPayload).timeStamp());
        if (toSend2 != null)
            send((BroadcastPacket) toSend2.setPacketData(sendPayload2).timeStamp());
    }

    protected void processOnion(UnicastPacket packet) {
        if (packet.getType() == PacketType.UnicastOnionCircuitBroken && packet.getPacketData(true) instanceof SinglePayload sp)
            deleteCircuit(sp.getPayload());
        else if (packet.getType() == PacketType.UnicastOnionCircuitCreated && packet.getPacketData(true) instanceof  CircuitCreatedPayload crtdp) {
            byte[] nid = crtdp.getNonceStream().readAllBytes();
            String oCID = nIDtoOnionCircuitID.remove(BytesToHex.bytesToHex(nid));
            if (oCID != null) {
                removeNID(nid);
                byte[] initKey = onionCircuitInitToEncryptionKey.get(oCID);
                GraphNode initNode = onionCircuitInitToInit.get(oCID);
                if (initKey != null && initNode != null) {
                    if (addCircuitID(crtdp.getCircuitID())) { // Success
                        try {
                            OnionPayload ocpy = new OnionPayload(new DataLayer(packet).encrypt(cryptoProvider.GetCryptorInstance().setKey(initKey))
                                    .setCircuitID(BytesToHex.hexToBytes(oCID)));
                            send((BroadcastPacket) new UnicastPacket(ocpy.getSize()).setDestinationAddress(initNode.ID).setSourceAddress(thisNode.ID).setTTL(maxTTL)
                                    .setPacketType(PacketType.UnicastOnion).setPacketData(ocpy).timeStamp());
                        } catch (GeneralSecurityException e) {
                            errors.add(e);
                        }
                    } else { // Fail, send broken to the remote
                        SinglePayload cpy = new SinglePayload(nid);
                        Packet toSendE = new UnicastPacket(cpy.getSize()).setDestinationAddress(thisNode.ID)
                                .setSourceAddress(packet.getSourceAddress()).setTTL(maxTTL).setPacketType(PacketType.UnicastOnionCircuitRejected)
                                .setPacketData(cpy).timeStamp().calculateHash(cryptoProvider.GetHasherInstance());
                        try {
                            OnionPayload ocpy = new OnionPayload(new DataLayer(toSendE).encrypt(cryptoProvider.GetCryptorInstance().setKey(initKey))
                                    .setCircuitID(BytesToHex.hexToBytes(oCID)));
                            send((BroadcastPacket) new UnicastPacket(ocpy.getSize()).setDestinationAddress(initNode.ID).setSourceAddress(thisNode.ID).setTTL(maxTTL)
                                    .setPacketType(PacketType.UnicastOnion).setPacketData(ocpy).timeStamp());
                        } catch (GeneralSecurityException e) {
                            errors.add(e);
                        }
                        cpy = new SinglePayload(crtdp.getCircuitID());
                        send((BroadcastPacket) new UnicastPacket(cpy.getSize()).setDestinationAddress(packet.getSourceAddress()).setSourceAddress(thisNode.ID)
                                .setTTL(maxTTL).setPacketType(PacketType.UnicastOnionCircuitBroken).setPacketData(cpy).timeStamp());
                    }
                }
            }
        } else if (packet.getType() == PacketType.UnicastOnionCircuitRejected && packet.getPacketData(true) instanceof SinglePayload sp) {
            String oCID = nIDtoOnionCircuitID.remove(BytesToHex.bytesToHex(sp.getPayload()));
            if (oCID != null) {
                removeNID(sp.getPayload());
                byte[] initKey = onionCircuitInitToEncryptionKey.get(oCID);
                GraphNode initNode = onionCircuitInitToInit.get(oCID);
                if (initKey != null && initNode != null) {
                    try {
                        OnionPayload ocpy = new OnionPayload(new DataLayer(packet).encrypt(cryptoProvider.GetCryptorInstance().setKey(initKey))
                                .setCircuitID(BytesToHex.hexToBytes(oCID)));
                        send((BroadcastPacket) new UnicastPacket(ocpy.getSize()).setDestinationAddress(initNode.ID).setSourceAddress(thisNode.ID).setTTL(maxTTL)
                                .setPacketType(PacketType.UnicastOnion).setPacketData(ocpy).timeStamp());
                    } catch (GeneralSecurityException e) {
                        errors.add(e);
                    }
                }
            }
        } else if ((packet.getType() == PacketType.UnicastOnionCircuitCreate
        || packet.getType() == PacketType.UnicastOnionCircuitCreateEndpoint) && packet.getPacketData(true) instanceof CircuitCreatePayload ccpl
        && ccpl.getWrappedKey() != null) {
            byte[] ocid = generateCircuitID();
            boolean reject = false;
            GraphNode eReg = null;
            try {
                byte[] ocKey = cryptoProvider.GetUnwrapperInstance().setPrivateKey(kemPrivateKey).unwrap(ccpl.getWrappedKey());
                onionCircuitInitToInit.put(BytesToHex.bytesToHex(ocid), network.get(BytesToHex.bytesToHex(packet.getSourceAddress())));
                onionCircuitInitToEncryptionKey.put(BytesToHex.bytesToHex(ocid), ocKey);
                if (packet.getType() == PacketType.UnicastOnionCircuitCreateEndpoint
                        && packet.getPacketData(true) instanceof CircuitCreateEndpointPayload ccepl) {
                    if (ccepl.getEtherealNodeID() != null) {
                        onionCircuitInitToOnionCircuitRemote.put(BytesToHex.bytesToHex(ocid), BytesToHex.bytesToHex(ccepl.getEtherealNodeID()));
                        eReg = new GraphNode(ccepl.getEtherealNodeID());
                        registerEtherealNode(eReg, thisNode);
                    } else {
                        removeCircuitID(ocid);
                        reject = true;
                    }
                }
                if (!reject) {
                    CircuitCreatedPayload ccdpl = new CircuitCreatedPayload(ccpl.getNonceStream(), ocid, cryptoProvider.GetCryptorInstance().setKey(ocKey).encrypt(ocKey));
                    send((BroadcastPacket) new UnicastPacket(ccdpl.getSize()).setDestinationAddress(packet.getSourceAddress())
                            .setSourceAddress(thisNode.ID).setTTL(maxTTL).setPacketType(PacketType.UnicastOnionCircuitCreated)
                            .setPacketData(ccdpl).timeStamp());
                    if (eReg != null) {
                        AssociatedPayload bPayload = new AssociatedPayload(eReg.ID, thisNode.ID);
                        send((BroadcastPacket) new BroadcastPacket(bPayload.getSize()).setSourceAddress(thisNode.ID).setTTL(maxTTL)
                                .setPacketType(PacketType.BroadcastAssociateEID).setPacketData(bPayload).timeStamp());
                    }
                }
            } catch (GeneralSecurityException e) {
                errors.add(e);
                removeCircuitID(ocid);
                reject = true;
                if (eReg != null)
                    removeNode(eReg);
            }
            if (reject) {
                SinglePayload rccpl = new SinglePayload(ccpl.getNonceStream().readAllBytes());
                send((BroadcastPacket) new UnicastPacket(rccpl.getSize()).setDestinationAddress(packet.getSourceAddress())
                        .setSourceAddress(thisNode.ID).setTTL(maxTTL).setPacketType(PacketType.UnicastOnionCircuitRejected)
                        .setPacketData(rccpl).timeStamp());
            }
        }
        else if (packet.getPacketData(true) instanceof OnionPayload onionPayload) {
            GraphNode csNode = onionCircuitInitToInit.get(onionPayload.getLayer().getCircuitIDString());
            if (csNode != null && Arrays.equals(csNode.ID, packet.getSourceAddress())) {
                byte[] initKey = onionCircuitInitToEncryptionKey.get(onionPayload.getLayer().getCircuitIDString());
                String remote = onionCircuitInitToOnionCircuitRemote.get(onionPayload.getLayer().getCircuitIDString());
                if (remote != null && initKey != null && remote.length() == 64) { // Ethereal relay out
                    GraphNode cdNode = network.get(remote);
                    if (onionPayload.getLayer() instanceof DataLayer odl) {
                        try {
                            Packet toSend = ((DataLayer) odl.decrypt(cryptoProvider.GetCryptorInstance().setKey(initKey))).getPacket();
                            if (toSend instanceof BroadcastPacket tsbpk && Arrays.equals(cdNode.ID, tsbpk.getSourceAddress()))
                                route((BroadcastPacket) toSend);
                        } catch (GeneralSecurityException e) {
                            errors.add(e);
                        }
                    }
                } else if (remote != null && initKey != null) { // Relay
                    GraphNode cdNode = onionCircuitRemoteToRemote.get(remote);
                    try {
                        OnionLayer nextLayer = onionPayload.getLayer().decrypt(cryptoProvider.GetCryptorInstance().setKey(initKey)).getSubLayer();
                        if (nextLayer != null) {
                            OnionPayload newPayload = new OnionPayload(nextLayer);
                            Packet toSend = new UnicastPacket(newPayload.getSize()).setDestinationAddress(cdNode.ID)
                                    .setSourceAddress(thisNode.ID).setTTL(maxTTL).setPacketType(PacketType.UnicastOnion)
                                    .setPacketData(newPayload).timeStamp();
                            send((BroadcastPacket) toSend);
                        }
                    } catch (GeneralSecurityException e) {
                        errors.add(e);
                    }
                } else if (initKey != null) { // Relay with no remote; accept only circuit creat
                    if (onionPayload.getLayer() instanceof DataLayer odl) {
                        try {
                            Packet toSend = ((DataLayer) odl.decrypt(cryptoProvider.GetCryptorInstance().setKey(initKey))).getPacket();
                            if (toSend instanceof UnicastPacket upkts && (upkts.getType() == PacketType.UnicastOnionCircuitCreate ||
                                    upkts.getType() == PacketType.UnicastOnionCircuitCreateEndpoint) &&
                                    toSend.getPacketData(true) instanceof CircuitCreatePayload ccp &&
                            Arrays.equals(upkts.getSourceAddress(),thisNode.ID)) {
                                byte[] cnid = ccp.getNonceStream().readAllBytes();
                                if (addNID(cnid)) {
                                    nIDtoOnionCircuitID.put(BytesToHex.bytesToHex(cnid), onionPayload.getLayer().getCircuitIDString());
                                } else {
                                    SinglePayload cpy = new SinglePayload(cnid);
                                    Packet toSendE = new UnicastPacket(cpy.getSize()).setDestinationAddress(thisNode.ID)
                                            .setSourceAddress(upkts.getDestinationAddress()).setTTL(maxTTL).setPacketType(PacketType.UnicastOnionCircuitRejected)
                                            .setPacketData(cpy).timeStamp().calculateHash(cryptoProvider.GetHasherInstance());
                                    OnionPayload ocpy = new OnionPayload(new DataLayer(toSendE).encrypt(cryptoProvider.GetCryptorInstance().setKey(initKey))
                                            .setCircuitID(onionPayload.getLayer().getCircuitID()));
                                    toSend = new UnicastPacket(ocpy.getSize()).setDestinationAddress(csNode.ID).setSourceAddress(thisNode.ID).setTTL(maxTTL)
                                            .setPacketType(PacketType.UnicastOnion).setPacketData(ocpy);
                                }
                                send((BroadcastPacket) toSend.timeStamp());
                            }
                        } catch (GeneralSecurityException e) {
                            errors.add(e);
                        }
                    }
                }
            } else { // Relay from remote
                csNode = onionCircuitRemoteToRemote.get(onionPayload.getLayer().getCircuitIDString());
                if (csNode != null && Arrays.equals(csNode.ID, packet.getSourceAddress())) {
                    String init = onionCircuitRemoteToOnionCircuitInit.get(onionPayload.getLayer().getCircuitIDString());
                    if (init != null) {
                        byte[] initKey = onionCircuitInitToEncryptionKey.get(init);
                        GraphNode cdNode = onionCircuitInitToInit.get(init);
                        if (initKey != null && cdNode != null) {
                            try {
                                OnionLayer nextLayer = new OnionLayer(onionPayload.getLayer()).encrypt(cryptoProvider.GetCryptorInstance()
                                        .setKey(initKey)).setCircuitID(BytesToHex.hexToBytes(init));
                                OnionPayload newPayload = new OnionPayload(nextLayer);
                                Packet toSend = new UnicastPacket(newPayload.getSize()).setDestinationAddress(cdNode.ID).setSourceAddress(thisNode.ID)
                                        .setTTL(maxTTL).setPacketType(PacketType.UnicastOnion).setPacketData(newPayload).timeStamp();
                                send((BroadcastPacket) toSend);
                            } catch (GeneralSecurityException e) {
                                errors.add(e);
                            }
                        }
                    }
                }
            }
        }
    }

    protected void processEtherealNode(BroadcastPacket packet, GraphNode eNode) {
        String initCID = onionCircuitRemoteToOnionCircuitInit.get(eNode.nodeID);
        if (initCID != null) { // Ethereal relay in
            byte[] initKey = onionCircuitInitToEncryptionKey.get(initCID);
            GraphNode initNode = onionCircuitInitToInit.get(initCID);
            if (initKey != null && initNode != null) {
                DataLayer upper = new DataLayer(packet);
                try {
                    upper.encrypt(cryptoProvider.GetCryptorInstance().setKey(initKey));
                } catch (GeneralSecurityException e) {
                    errors.add(e);
                    return;
                }
                OnionPayload payload = new OnionPayload(upper.setCircuitID(BytesToHex.hexToBytes(initCID)));
                UnicastPacket packetToSend = (UnicastPacket) new UnicastPacket(payload.getSize()).setDestinationAddress(initNode.ID)
                        .setTTL(maxTTL).setPacketType(PacketType.UnicastOnion).setPacketData(payload).timeStamp();
                send(packetToSend);
            }
        }
    }

    protected void processEthereal(UnicastPacket packet) {
        String initCID = onionCircuitRemoteToOnionCircuitInit.get(BytesToHex.bytesToHex(packet.getDestinationAddress()));
        if (initCID != null) {
            GraphNode initNode = onionCircuitInitToInit.get(initCID);
            if (initNode != null)
                processEtherealNode(packet, initNode);
        }
    }

    protected byte[] generateCircuitID() {
        byte[] circuitID = new byte[16];
        synchronized (lockOnionCircuitIDs) {
            boolean contained = true;
            while (contained) {
                random.nextBytes(circuitID);
                contained = onionCircuitIDs.contains(BytesToHex.bytesToHex(circuitID));
            }
            onionCircuitIDs.add(BytesToHex.bytesToHex(circuitID));
        }
        return circuitID;
    }

    //*
    protected boolean addCircuitID(byte[] circuitID) {
        synchronized (lockOnionCircuitIDs) {
            if (onionCircuitIDs.contains(BytesToHex.bytesToHex(circuitID)))
                return false;
            onionCircuitIDs.add(BytesToHex.bytesToHex(circuitID));
            return true;
        }
    }

    protected void removeCircuitIDString(String circuitIDStr) {
        synchronized (lockOnionCircuitIDs) {
            onionCircuitIDs.remove(circuitIDStr);
        }
    }

    protected void removeCircuitID(byte[] circuitID) {
        removeCircuitIDString(BytesToHex.bytesToHex(circuitID));
    }

    //*
    protected byte[] generateNID() {
        byte[] NID = new byte[16];
        synchronized (locknIDs) {
            boolean contained = true;
            while (contained) {
                random.nextBytes(NID);
                contained = nIDs.contains(BytesToHex.bytesToHex(NID));
            }
            nIDs.add(BytesToHex.bytesToHex(NID));
        }
        return NID;
    }

    protected boolean addNID(byte[] NID) {
        synchronized (locknIDs) {
            if (nIDs.contains(BytesToHex.bytesToHex(NID)))
                return false;
            nIDs.add(BytesToHex.bytesToHex(NID));
            return true;
        }
    }

    protected void removeNIDString(String NIDStr) {
        synchronized (locknIDs) {
            nIDs.remove(NIDStr);
        }
    }

    protected void removeNID(byte[] NID) {
        removeNIDString(BytesToHex.bytesToHex(NID));
    }

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
            if (ownsAddress(BytesToHex.hexToBytes(address)))
                return null;
            if (address == null) {
                GraphNode[] nhs = new GraphNode[hopObjects.size()];
                nhs = hopObjects.toArray(nhs);
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
            List<GraphNode> missingNetwork = new ArrayList<>(network.values());
            nextHop.clear();
            hopObjects.clear();
            hopObjects.addAll(thisNode.siblings);
            Map<GraphNode, NodeHopInfo> hopInfoStore = new HashMap<>();
            for (GraphNode node : hopObjects) {
                hopInfoStore.put(node, new NodeHopInfo(node, 0));
                hopProcessor(hopInfoStore, node, node, 0);
            }
            missingNetwork.removeAll(thisNode.etherealNodes); // Auto-detect missing nodes, exclude this node and its ethereals
            missingNetwork.remove(thisNode);
            for (Map.Entry<GraphNode, NodeHopInfo> entry : hopInfoStore.entrySet()) {
                nextHop.put(entry.getKey().nodeID, entry.getValue().connectedTransport);
                missingNetwork.remove(entry.getKey());
                for (GraphNode eNode : entry.getKey().etherealNodes) {
                    nextHop.put(eNode.nodeID, entry.getValue().connectedTransport);
                    missingNetwork.remove(eNode);
                }
            }
            for (GraphNode node : missingNetwork)
                removeNode(node);
        }
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
        packet.decrementTTL();
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

    /**
     * Make sure all packets are signed before being received.
     *
     * @param toCharge The packet to charge.
     * @return The packet or null.
     */
    private Packet chargePacket(Packet toCharge) {
        if (toCharge == null)
            return null;
        PacketStore store;
        byte[] pkHash;
        String pkHashStr;
        SignaturePayload signaturePayload = null;
        if ((toCharge.getType() == PacketType.BroadcastSignature || toCharge.getType() == PacketType.UnicastSignature
        || toCharge.getType() == PacketType.DirectSignature)
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
        if (store == null) { // Allocate new store if packet not found by hash
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
            synchronized (store) { // Set store contents
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
                while (store.packetHash == null) {  // Wait until store has a hash
                    try {
                        store.wait();
                    } catch (InterruptedException ignored) {
                        return null;
                    }
                }
                if (signaturePayload != null) { // Update store contents
                    if (store.signatureHash == null)
                        store.signatureHash = signaturePayload.getSignatureHash().readAllBytes();
                    else {
                        try {
                            if (!StreamEquals.streamEqualsArray(signaturePayload.getSignatureHash(), store.signatureHash))
                                return null;
                        } catch (IOException e) {
                            errors.add(e);
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
        synchronized (store) { // Check if store is now ready to be received
            Packet toret = null;
            byte[] sig = SignaturePayload.getSignatureFromFragments(store.packetSignature, store.signatureHash, cryptoProvider.GetHasherInstance());
            if (sig.length > 0 && store.packet instanceof BroadcastPacket bpk) {
                GraphNode cNode = network.get(BytesToHex.bytesToHex(bpk.getSourceAddress()));
                if (cNode != null) {
                    if (store.packet.validateWithSignature(cryptoProvider.GetHasherInstance(), cryptoProvider.GetVerifierInstance().setPublicKey(cNode.dsaKey), sig))
                        toret = store.packet;
                    synchronized (packetChargeLock) {
                        store.olderStore.newerStore = store.newerStore;
                        store.newerStore.olderStore = store.olderStore;
                        store.nextFreeStore = freeStore;
                        freeStore = store;
                        packetStore.remove(pkHashStr);
                    }
                }
            }
            return toret;
        }
    }

    protected void route(BroadcastPacket packet) {
        GraphNode[] dests;
        if (packet instanceof UnicastPacket upk)
            dests = getNextHops(BytesToHex.bytesToHex(upk.getDestinationAddress()));
        else {
            dests = getNextHops(null);
            processPacket(packet);
        }
        if (dests == null) {
            processPacket(packet);
            return;
        }
        for (GraphNode node : dests) {
            if (node.transport != null)
                node.transport.send(packet.getPacketBytes());
        }
    }

    //*
    protected void send(BroadcastPacket packet) {
        byte[] key = null;
        PacketType pt = packet.getType();
        if (pt != PacketType.UnicastSignature && pt != PacketType.UnicastEncryptionRejectedHandshake &&
                pt != PacketType.UnicastEncryptionRequestHandshake &&
                pt != PacketType.UnicastEncryptionResponseHandshake &&
                pt != PacketType.UnicastOnionCircuitCreate && pt != PacketType.UnicastOnionCircuitBroken &&
                pt != PacketType.UnicastOnionCircuitCreateEndpoint && pt != PacketType.UnicastOnionCircuitCreated &&
                pt != PacketType.UnicastOnionCircuitRejected
        && !Arrays.equals(packet.getSourceAddress(), thisNode.ID)) { // Packet type not a handshake (Handshake encryption not allowed) or source from thisNode
            if (packet instanceof UnicastPacket upk) {
                GraphNode dest = network.get(BytesToHex.bytesToHex(upk.getDestinationAddress()));
                if (dest != null) {
                    key = dest.getEncryptionKey();
                    if (key == null && e2eEnabled && requireE2E && !dest.stopEncryptionRequests)
                        key = sendEncryptionHandshake(dest);
                }
            }
        }
        if (key == null && e2eEnabled && requireE2E && packet instanceof UnicastPacket)
            return;
        try {
            if (key != null)
                packet.Encrypt(cryptoProvider.GetCryptorInstance().setKey(key));
            packet.calculateHash(cryptoProvider.GetHasherInstance());
            Packet[] sigp = packet.getSignaturePackets(cryptoProvider.GetHasherInstance(), cryptoProvider.GetSignerInstance().setPrivateKey(dsaPrivateKey), 1210);
            for (Packet p : sigp) {
                p.calculateHash(cryptoProvider.GetHasherInstance());
                route((BroadcastPacket) p);
            }
            route(packet);
        } catch (GeneralSecurityException e) {
            errors.add(e);
        }
    }

    private byte[] sendEncryptionHandshake(GraphNode target) {
        byte[] key = new byte[32];
        random.nextBytes(key);
        try {
            SinglePayload enchp = new SinglePayload(cryptoProvider.GetWrapperInstance().setPublicKey(target.kemKey).wrap(key));
            target.setEncryptionKey(key, Instant.now().getEpochSecond());
            updates.add(new NodeUpdate(target, false));
            send((BroadcastPacket) new UnicastPacket(enchp.getSize()).setDestinationAddress(target.ID)
                    .setSourceAddress(thisNode.ID).setTTL(maxTTL).setPacketType(PacketType.UnicastEncryptionRequestHandshake).setPacketData(enchp)
                    .timeStamp());
            return key;
        } catch (GeneralSecurityException e) {
            errors.add(e);
            return null;
        }
    }

    //*
    protected void receive(BroadcastPacket packet) {
        if (packet instanceof UnicastPacket upk && !Arrays.equals(upk.getDestinationAddress(), thisNode.ID)) {
            receiveQueue.add(packet);
            return; //Code to process handshake translated extra packets
        }
        packet = (BroadcastPacket) chargePacket(packet);
        if (packet != null) {
            GraphNode sour = network.get(BytesToHex.bytesToHex(packet.getSourceAddress()));
            if (packet.isEncrypted() && e2eEnabled) {
                if (sour != null) {
                    byte[] key = sour.getEncryptionKey();
                    if (key != null) {
                        try {
                            packet.Decrypt(cryptoProvider.GetCryptorInstance().setKey(key));
                        } catch (GeneralSecurityException e) {
                            errors.add(e);
                            return;
                        }
                    }
                }
            } else if (e2eEnabled && requireE2E && !Arrays.equals(packet.getSourceAddress(), thisNode.ID)
            && packet instanceof UnicastPacket && !sour.stopEncryptionRequests) {
                sendEncryptionHandshake(sour);
                if (ignoreNonE2E)
                    return;
            }
            receiveQueue.add(packet);
        }
    }

    /**
     * Gets a node ID given a string IP address.
     *
     * @param addressIP The IP address as hex.
     * @return The ID of the associated node.
     */
    public byte[] getNodeID(String addressIP) {
        GraphNode n = networkAddresses.get(addressIP);
        if (n == null)
            return null;
        return n.ID;
    }

    /**
     * Gets the ID of this node.
     *
     * @return The ID of this node.
     */
    public byte[] getThisNodeID() {
        return thisNode.ID;
    }

    /**
     * Gets the current gateway node ID, if any.
     *
     * @return The gateway ID or null.
     */
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
        return ownsAddress(BytesToHex.hexToBytes(address)) || getNextHops(address).length > 0;
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

        public DataLinkProcessor start() {
            AssociatedPayload bPayload = new AssociatedPayload(linkedNode.ID, linkedNode.kemKey);
            send((BroadcastPacket) new BroadcastPacket(bPayload.getSize()).setSourceAddress(thisNode.ID).setTTL(maxTTL)
                    .setPacketType(PacketType.BroadcastAssociateKEMKey).setPacketData(bPayload).timeStamp());
            bPayload = new AssociatedPayload(linkedNode.ID, linkedNode.dsaKey);
            send((BroadcastPacket) new BroadcastPacket(bPayload.getSize()).setSourceAddress(thisNode.ID).setTTL(maxTTL)
                    .setPacketType(PacketType.BroadcastAssociateDSAKey).setPacketData(bPayload).timeStamp());
            recvThread.setDaemon(true);
            recvThread.start();
            return this;
        }

        @Override
        public void run() {
            try {
                while (active && dataLink.isActive()) {
                    byte[] data = dataLink.receive();
                    if (data == null)
                        return;
                    Packet pk = Packet.getPacketFromBytes(data);
                    if (pk.getType() == PacketType.Unknown || !pk.timeStampInRange() || !pk.verifyHash(cryptoProvider.GetHasherInstance()))
                        continue;
                    if (pk.getType().getMessagingType() == PacketMessagingType.Direct) {
                        Packet pkc = chargePacket(pk);
                        if (pkc != null) {
                            if (pkc.getType() == PacketType.DirectGatewayAvailable) {
                                linkedNode.isGateway = true;
                                gateways.add(linkedNode);
                            } else if (pkc.getType() == PacketType.DirectGraphing || pkc.getType() == PacketType.DirectNodesEID) {
                                pk = new BroadcastPacket(pkc.getPayloadSize()).setSourceAddress(linkedNode.ID)
                                        .setPacketData(pkc.getPacketData(true)).setPacketType(pkc.getType());
                                receiveQueue.add(pk);
                            }
                        }
                    } else
                        processPacket(pk);
                }
                linkedNode.transport = null;
                if (dataLink.isActive())
                    dataLink.close();
                dataLinks.remove(linkedNode.nodeID);
                dataLinkList.remove(this);
                AssociatePayload bPayload = new AssociatePayload(linkedNode.ID);
                send((BroadcastPacket) new BroadcastPacket(bPayload.getSize()).setSourceAddress(thisNode.ID).setTTL(maxTTL)
                        .setPacketType(PacketType.BroadcastNodeDead).setPacketData(bPayload).timeStamp());
                for (GraphNode eNode : linkedNode.etherealNodes) {
                    bPayload = new AssociatePayload(eNode.ID);
                    send((BroadcastPacket) new BroadcastPacket(bPayload.getSize()).setSourceAddress(thisNode.ID).setTTL(maxTTL)
                            .setPacketType(PacketType.BroadcastDeAssociateEID).setPacketData(bPayload).timeStamp());
                }
                removeNode(linkedNode);
            } catch (RuntimeException e) {
                errors.add(e);
            }
        }
    }

    /**
     * Gets the first Exception.
     *
     * @return The first exception received.
     * @throws InterruptedException Thread was interrupted.
     */
    public Exception getFirstException() throws InterruptedException {
        return errors.take();
    }

    /**
     * Provides a class for node updates.
     */
    public static class NodeUpdate {
        public GraphNode node;
        public boolean removed;
        NodeUpdate(GraphNode node, boolean removed) {
            this.node = node;
            this.removed = removed;
        }
    }

    /**
     * Gets the first node update.
     *
     * @return The first node update.
     * @throws InterruptedException Thread was interrupted.
     */
    public NodeUpdate getFirstUpdate() throws InterruptedException {
        return updates.take();
    }
}
