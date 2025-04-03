package com.captainalm.lib.mesh.packets;

/**
 * Provides the type of packet.
 * The types of packets and how they work / are structured are specified in the design RFC for the protocol.
 *
 * @author Alfred Manville
 */
public enum PacketType {
    Unknown(0),
    DirectHandshakeKEMKey(1),
    DirectHandshakeDSAKey(2),
    DirectHandshakeIDSignature(3),
    DirectHandshakeDSARecommendationKey(4),
    DirectHandshakeDSARecommendationSignature(5),
    DirectHandshakeAccept(6),
    DirectHandshakeReject(7),
    DirectGraphing(8),
    DirectNodesEID(9),
    DirectGatewayAvailable(10),
    DirectSignature(11),
    BroadcastGateway(12),
    BroadcastGraphing(13),
    BroadcastNodeDead(14),
    BroadcastAssociateEID(15),
    BroadcastAssociateKEMKey(16),
    BroadcastAssociateDSAKey(17),
    BroadcastDeAssociateEID(18),
    BroadcastSignature(19),
    UnicastData(20),
    UnicastDataAddressed(21),
    UnicastOnion(22),
    UnicastEncryptionRequestHandshake(23),
    UnicastEncryptionResponseHandshake(24),
    UnicastEncryptionRejectedHandshake(25),
    UnicastOnionCircuitCreate(26),
    UnicastOnionCircuitCreateEndpoint(27),
    UnicastOnionCircuitCreated(28),
    UnicastOnionCircuitRejected(29),
    UnicastOnionCircuitBroken(30),
    UnicastSignature(31);
    private final byte id;

    PacketType(int id) {
        this.id = (byte) id;
    }

    /**
     * Gets the ID byte of the packet.
     *
     * @return The ID byte.
     */
    public byte getID() {
        return id;
    }

    /**
     * Gets the ID byte of the packet with the encrypted bit set.
     *
     * @return The ID byte.
     */
    public byte getEncryptedID() {
        return (byte) (id | (1 << 7));
    }

    /**
     * Gets the packet type from the ID byte; the encrypted bit is ignored.
     *
     * @param id The ID byte.
     * @return The packet type.
     */
    public static PacketType fromID(byte id) {
        if (isEncryptedID(id))
            id &= (byte) ~(1 << 7);
        switch (id) {
            case 1:
                return DirectHandshakeKEMKey;
            case 2:
                return DirectHandshakeDSAKey;
            case 3:
                return DirectHandshakeIDSignature;
            case 4:
                return DirectHandshakeDSARecommendationKey;
            case 5:
                return DirectHandshakeDSARecommendationSignature;
            case 6:
                return DirectHandshakeAccept;
            case 7:
                return DirectHandshakeReject;
            case 8:
                return DirectGraphing;
            case 9:
                return DirectNodesEID;
            case 10:
                return DirectGatewayAvailable;
            case 11:
                return DirectSignature;
            case 12:
                return BroadcastGateway;
            case 13:
                return BroadcastGraphing;
            case 14:
                return BroadcastNodeDead;
            case 15:
                return BroadcastAssociateEID;
            case 16:
                return BroadcastAssociateKEMKey;
            case 17:
                return BroadcastAssociateDSAKey;
            case 18:
                return BroadcastDeAssociateEID;
            case 19:
                return BroadcastSignature;
            case 20:
                return UnicastData;
            case 21:
                return UnicastDataAddressed;
            case 22:
                return UnicastOnion;
            case 23:
                return UnicastEncryptionRequestHandshake;
            case 24:
                return UnicastEncryptionResponseHandshake;
            case 25:
                return UnicastEncryptionRejectedHandshake;
            case 26:
                return UnicastOnionCircuitCreate;
            case 27:
                return UnicastOnionCircuitCreateEndpoint;
            case 28:
                return UnicastOnionCircuitCreated;
            case 29:
                return UnicastOnionCircuitRejected;
            case 30:
                return UnicastOnionCircuitBroken;
            case 31:
                return UnicastSignature;
        }
        return Unknown;
    }

    /**
     * Gets the packet {@link PacketMessagingType}.
     *
     * @return The messaging type.
     */
    public PacketMessagingType getMessagingType() {
        if (id >= 0 && id < 12) {
            return PacketMessagingType.Direct;
        } else if (id > 11 && id < 20) {
            return PacketMessagingType.Broadcast;
        } else {
            return PacketMessagingType.Unicast;
        }
    }

    /**
     * Gets if the provided packet ID byte signifies that its encrypted.
     *
     * @param id The packet ID byte.
     * @return If the encrypted bit is set.
     */
    public static boolean isEncryptedID(byte id) {
        return (id & (byte) (1 << 7)) != 0;
    }
}
