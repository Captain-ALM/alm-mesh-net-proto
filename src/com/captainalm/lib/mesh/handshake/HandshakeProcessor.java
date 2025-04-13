package com.captainalm.lib.mesh.handshake;

import com.captainalm.lib.mesh.crypto.IProvider;
import com.captainalm.lib.mesh.packets.Packet;
import com.captainalm.lib.mesh.packets.PacketType;
import com.captainalm.lib.mesh.packets.data.AssociatedPayload;
import com.captainalm.lib.mesh.packets.data.PacketData;
import com.captainalm.lib.mesh.packets.data.SignaturePayload;
import com.captainalm.lib.mesh.packets.data.SinglePayload;
import com.captainalm.lib.mesh.routing.graphing.GraphNode;
import com.captainalm.lib.mesh.transport.INetTransport;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Provides a way of handshaking two transports before routing commences.
 *
 * @author Alfred Manville
 */
public final class HandshakeProcessor {
    private final INetTransport transport;
    private final List<Packet> packets = new LinkedList<>();
    private final IProvider cProvider;
    private final IPeerAuthorizer authorizer;

    private Packet dsaPacket;
    private Packet kemPacket;
    private SignaturePayload[] sigPayloads;

    private Packet recSigPubPacket;
    private SignaturePayload[] recSigPayloads;

    private Packet finalPacket;
    private SignaturePayload[] finalSigPayloads;

    private boolean failed = false;
    private Boolean noRecommendations = null;
    private boolean recommendProcessed = false;
    private byte[] encKey;

    private final GraphNode local;
    private GraphNode remote;

    private final byte[] kemPrivateKey;
    private final byte[] dsaPrivateKey;
    private final byte[] myEncKey;

    private final BlockingQueue<Exception> errors = new LinkedBlockingQueue<>();

    private final Object lockNotify = new Object();
    private final Thread recvThread = new Thread(new Runnable() {
        @Override
        public void run() {
            try {
                while (transport.isActive() && !failed && encKey == null) {
                    byte[] data = transport.receive();
                    if (data == null)
                        return;
                    Packet pk = Packet.getPacketFromBytes(data);
                    if (pk.getType() == PacketType.Unknown || !pk.timeStampInRange() || !pk.verifyHash(cProvider.GetHasherInstance()))
                        continue;
                    switch (pk.getType()) {
                        case DirectHandshakeNoRecommendation -> noRecommendations = true;
                        case DirectHandshakeKEMKey -> kemPacket = pk;
                        case DirectHandshakeDSAKey -> dsaPacket = pk;
                        case DirectHandshakeIDSignature -> sigPayloads = recvSigPacket(pk, sigPayloads);
                        case DirectHandshakeDSARecommendationKey -> recSigPubPacket = pk;
                        case DirectHandshakeDSARecommendationSignature ->
                                recSigPayloads = recvSigPacket(pk, recSigPayloads);
                        case DirectHandshakeAccept, DirectHandshakeReject -> {
                            if (finalPacket == null)
                                finalPacket = pk;
                        }
                        case DirectHandshakeSignature -> finalSigPayloads = recvSigPacket(pk, finalSigPayloads);
                        default -> packets.add(pk);
                    }
                    if (remote == null) {
                        if (kemPacket != null && dsaPacket != null && sigPayloads != null) {
                            boolean bail = false;
                            for (SignaturePayload p : sigPayloads) {
                                if (p == null) {
                                    bail = true;
                                    break;
                                }
                            }
                            if (bail)
                                continue;
                            byte[] sig = SignaturePayload.getSignatureFromFragments(sigPayloads, sigPayloads[0].getSignatureHash().readAllBytes(), cProvider.GetHasherInstance());
                            if (kemPacket.getPacketData(true) instanceof AssociatedPayload asdp1
                                    && dsaPacket.getPacketData(true) instanceof AssociatedPayload asdp2
                                    && Arrays.equals(asdp1.getAssociateID(), asdp2.getAssociateID())) {
                                // The ID itself is signed rather than a hash of this data
                                byte[] ID = new byte[32];
                                System.arraycopy(cProvider.GetHasherInstance().hash(asdp1.getAssociatedPayload()), 0, ID, 0, 16);
                                System.arraycopy(cProvider.GetHasherInstance().hash(asdp2.getAssociatedPayload()), 0, ID, 16, 16);
                                try {
                                    if (Arrays.equals(ID, asdp1.getAssociateID()) && Arrays.equals(ID, sigPayloads[0].getDataHash().readAllBytes())
                                            && sig.length > 0 && cProvider.GetVerifierInstance().setPublicKey(asdp2.getAssociatedPayload()).verify(ID, sig)) {
                                        // In this case, data hash is the pure ID
                                        remote = new GraphNode(ID);
                                        remote.kemKey = asdp1.getAssociatedPayload();
                                        remote.dsaKey = asdp2.getAssociatedPayload();
                                        remote.transport = transport;
                                    } else {
                                        failed = true;
                                    }
                                } catch (GeneralSecurityException e) {
                                    errors.add(e);
                                    failed = true;
                                }
                            } else {
                                failed = true;
                            }
                            synchronized (lockNotify) {
                                lockNotify.notifyAll();
                            }
                        }
                    } else {
                        if (!failed && !recommendProcessed && (noRecommendations != null || (recSigPayloads != null && recSigPubPacket != null))) {
                            if (noRecommendations == null) {
                                boolean bail = false;
                                for (SignaturePayload p : recSigPayloads) {
                                    if (p == null) {
                                        bail = true;
                                        break;
                                    }
                                }
                                if (bail)
                                    continue;
                                byte[] sig2 = SignaturePayload.getSignatureFromFragments(recSigPayloads, recSigPayloads[0].getSignatureHash().readAllBytes(), cProvider.GetHasherInstance());
                                try {
                                    if (Arrays.equals(remote.ID, recSigPayloads[0].getDataHash().readAllBytes())
                                            && sig2.length > 0 && recSigPubPacket.getPacketData(true) instanceof SinglePayload sp
                                            && cProvider.GetVerifierInstance().setPublicKey(sp.getPayload()).verify(remote.ID, sig2)) {
                                        noRecommendations = false;
                                    } else {
                                        noRecommendations = true;
                                    }
                                } catch (GeneralSecurityException e) {
                                    errors.add(e);
                                    noRecommendations = true;
                                }
                            }
                            recommendProcessed = true;
                            synchronized (lockNotify) {
                                lockNotify.notifyAll();
                            }
                        } else if (!failed && recommendProcessed && finalPacket != null && finalSigPayloads != null) {
                            boolean bail = false;
                            for (SignaturePayload p : finalSigPayloads) {
                                if (p == null) {
                                    bail = true;
                                    break;
                                }
                            }
                            if (bail)
                                continue;
                            byte[] sig = SignaturePayload.getSignatureFromFragments(finalSigPayloads, finalSigPayloads[0].getSignatureHash().readAllBytes(), cProvider.GetHasherInstance());
                            try {
                                if (Arrays.equals(finalPacket.getHash(), finalSigPayloads[0].getDataHash().readAllBytes()) &&
                                        sig.length > 0 && cProvider.GetVerifierInstance().setPublicKey(remote.dsaKey).verify(finalPacket.getHash(), sig)) {
                                    if (finalPacket.getType() == PacketType.DirectHandshakeAccept && finalPacket.getPacketData(true) instanceof SinglePayload sp) {
                                        encKey = cProvider.GetUnwrapperInstance().setPrivateKey(kemPrivateKey).unwrap(sp.getPayload());
                                    } else {
                                        failed = true;
                                    }
                                } else {
                                    failed = true;
                                }
                            } catch (GeneralSecurityException e) {
                                errors.add(e);
                                failed = true;
                            }
                            synchronized (lockNotify) {
                                lockNotify.notifyAll();
                            }
                        }
                    }
                }
            } catch (RuntimeException e) {
                errors.add(e);
            }
        }
    });

    private SignaturePayload[] recvSigPacket(Packet pk, SignaturePayload[] sigPks) {
        if (pk.getPacketData(true) instanceof SignaturePayload sigp) {
            if (sigPks == null)
                sigPks = new SignaturePayload[sigp.getMaxParts()];
            else if (sigp.getPartID() < sigPks.length)
                sigPks[sigp.getPartID()] = sigp;
        }
        return sigPks;
    }

    /**
     * Constructs a new instance of HandshakeProcessor with the specified local node imformation,
     * transport, cryptographic provider, authorizer and private keys.
     *
     * @param local The local node.
     * @param transport The transport.
     * @param cryptProvider The cryptographic provider.
     * @param authorizer The peer authorizer.
     * @param kemPrivateKey The ml-kem private key.
     * @param dsaPrivateKey The ml-dsa private key.
     * @param myEncKey this node's symmetric encryption key.
     * @throws IllegalArgumentException parameter cannot be null
     */
    public HandshakeProcessor(GraphNode local, INetTransport transport, IProvider cryptProvider,
                              IPeerAuthorizer authorizer, byte[] kemPrivateKey, byte[] dsaPrivateKey, byte[] myEncKey) {
        if (local == null || transport == null || cryptProvider == null || authorizer == null || kemPrivateKey == null || dsaPrivateKey == null || myEncKey == null)
            throw new IllegalArgumentException("parameter cannot be null");
        this.local = local;
        this.transport = transport;
        this.cProvider = cryptProvider;
        this.authorizer = authorizer;
        this.kemPrivateKey = kemPrivateKey;
        this.dsaPrivateKey = dsaPrivateKey;
        this.myEncKey = myEncKey;
    }

    private void send(PacketData payload, PacketType type, boolean sendSignatures) throws GeneralSecurityException {
        Packet toSend = new Packet((payload == null) ? 0 : payload.getSize()).setPacketType(type);
        if (payload != null)
            toSend.setPacketData(payload);
        toSend.timeStamp().calculateHash(cProvider.GetHasherInstance());
        transport.send(toSend.getPacketBytes());
        if (sendSignatures) {
            Packet[] toSendSigs = toSend.getSignaturePackets(cProvider.GetHasherInstance(), cProvider.GetSignerInstance().setPrivateKey(dsaPrivateKey), 1210);
            for (Packet p : toSendSigs)
                transport.send(p.setPacketType(PacketType.DirectHandshakeSignature).calculateHash(cProvider.GetHasherInstance()).getPacketBytes());
        }
    }

    /**
     * Handshakes on the transport.
     *
     * @param timeout Aa timeout during one of the 3 response wait cycles.
     * @return The shared session key or null of failure.
     * @throws InterruptedException The handshake was interrupted on-thread.
     */
    public byte[] handshake(int timeout) throws InterruptedException {
        return handshake(timeout, null, null);
    }

    /**
     * Handshakes on the transport with the specified recommendation.
     *
     * @param timeout Aa timeout during one of the 3 response wait cycles.
     * @param publicRecommendKey The public key used to verify the recommendation.
     * @param recommendSignature The signature of this node ID using the recommendation private key.
     * @return The shared session key or null of failure.
     * @throws InterruptedException The handshake was interrupted on-thread.
     */
    public byte[] handshake(int timeout, byte[] publicRecommendKey, byte[] recommendSignature) throws InterruptedException {
        if (failed) return null;
        if (encKey != null) return encKey;
        recvThread.setDaemon(true);
        recvThread.start();
        try {
            send(new AssociatedPayload(local.ID, local.kemKey), PacketType.DirectHandshakeKEMKey, false);
            send(new AssociatedPayload(local.ID, local.dsaKey), PacketType.DirectHandshakeDSAKey, false);
        } catch (GeneralSecurityException e) {
            errors.add(e);
            failed = true;
            return null;
        }
        try {
            SignaturePayload[] sigs = SignaturePayload.getFragmentedSignature(cProvider.GetSignerInstance().setPrivateKey(dsaPrivateKey)
                    .sign(local.ID), local.ID, cProvider.GetHasherInstance(), 1210);
            for (SignaturePayload sig : sigs)
                send(sig, PacketType.DirectHandshakeIDSignature, false);
        } catch (GeneralSecurityException e) {
            errors.add(e);
            failed = true;
            return null;
        }
        synchronized (lockNotify) {
            while (remote == null)
                lockNotify.wait(timeout);
        }
        try {
        if (publicRecommendKey == null || recommendSignature == null) {
            send(null, PacketType.DirectHandshakeNoRecommendation, false);
        } else {
            send(new SinglePayload(publicRecommendKey), PacketType.DirectHandshakeDSARecommendationKey, false);
            SignaturePayload[] sigs = SignaturePayload.getFragmentedSignature(recommendSignature,
                    cProvider.GetHasherInstance().hash(recommendSignature), cProvider.GetHasherInstance(), 1210);
            for (SignaturePayload sig : sigs)
                send(sig, PacketType.DirectHandshakeDSARecommendationSignature, false);
        }
        } catch (GeneralSecurityException e) {
            errors.add(e);
            failed = true;
            return null;
        }
        synchronized (lockNotify) {
            while (remote == null)
                lockNotify.wait(timeout);
        }
        try {
            if (authorizer.authorize(remote.ID, (noRecommendations) ? null : ((SinglePayload) recSigPubPacket.getPacketData(true)).getPayload()))
                send(new SinglePayload(cProvider.GetWrapperInstance().setPublicKey(remote.kemKey).wrap(myEncKey)), PacketType.DirectHandshakeAccept, true);
            else
                send(null, PacketType.DirectHandshakeReject, true);
        } catch (GeneralSecurityException e) {
            errors.add(e);
            failed = true;
            return null;
        }
        synchronized (lockNotify) {
            while (remote == null)
                lockNotify.wait(timeout);
        }
        return encKey;
    }

    /**
     * Gets the remote node or null.
     *
     * @return The remote node or null.
     */
    public GraphNode getRemote() {
        return remote;
    }

    /**
     * Gets a list of other received direct packets.
     *
     * @return The list of packets.
     */
    public List<Packet> getOtherPackets() {
        return packets;
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
}
