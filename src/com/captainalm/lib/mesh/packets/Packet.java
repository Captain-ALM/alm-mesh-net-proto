package com.captainalm.lib.mesh.packets;

import com.captainalm.lib.mesh.crypto.ICryptor;
import com.captainalm.lib.mesh.crypto.IHasher;
import com.captainalm.lib.mesh.crypto.ISigner;
import com.captainalm.lib.mesh.crypto.IVerifier;
import com.captainalm.lib.mesh.packets.data.PacketData;
import com.captainalm.lib.mesh.packets.data.SignaturePayload;
import com.captainalm.lib.mesh.utils.ByteBufferOverwriteOutputStream;
import com.captainalm.lib.mesh.utils.IntOnStream;
import com.captainalm.lib.mesh.utils.StreamEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Instant;

/**
 * Provides ease of access to read and write packet fields.
 * The TTL and hash are excluded from the hash.
 *
 * @author Alfred Manville
 */
public class Packet {
    protected byte[] data;
    protected Short length;
    protected Long timeStamp;

    public static final int MIN_SIZE = 44;

    /**
     * Creates a new packet with a specified payload size.
     *
     * @param size The size of the payload.
     * @throws IllegalArgumentException size is too small or too big.
     */
    public Packet(int size) {
        if (size < 0 || size > Short.MAX_VALUE)
            throw new IllegalArgumentException("size must be between 0 and Short.MAX_VALUE");
        this.data = new byte[getPacketDataStartIndex() + size + 32];
        try {
            IntOnStream.WriteShort(new ByteBufferOverwriteOutputStream(this.data, 2, 2), (short) size);
        } catch (IOException ignored) {
        }
        this.length = (short) size;
    }

    /**
     * Creates a packet from its data representation.
     *
     * @param packet The packet data.
     */
    public Packet(byte[] packet) {
        this.data = packet;
    }

    /**
     * Gets the packet's data representation.
     * NOTE: If you've changed the contents of a packet, use {@link #getPacketBytesHashNow(IHasher)}
     * instead or call {@link #calculateHash(IHasher)} before this method.
     *
     * @return The packet data.
     */
    public byte[] getPacketBytes() {
        return data;
    }

    /**
     * Gets the packet's data representation after calculating the packet hash.
     *
     * @param hProvider The {@link IHasher} to use.
     * @return The packet data.
     */
    public byte[] getPacketBytesHashNow(IHasher hProvider) {
        calculateHash(hProvider);
        return data;
    }

    /**
     * Gets the {@link PacketType}.
     *
     * @return The packet type.
     */
    public PacketType getType() {
        if (data == null || data.length < 2) return null;
        return PacketType.fromID(data[1]);
    }

    /**
     * Sets the {@link PacketType}
     *
     * @param type The packet type.
     * @return This instance of Packet.
     */
    public Packet setPacketType(PacketType type) {
        if (data == null || data.length < 2) return this;
        data[1] = type.getID();
        return this;
    }

    /**
     * Gets if the packet has been encrypted.
     *
     * @return If the packet is encrypted.
     */
    public boolean isEncrypted() {
        if (data == null || data.length < 2) return false;
        return PacketType.isEncryptedID(data[1]);
    }

    /**
     * Gets the data object that represents the packet payload.
     *
     * @return The packet payload.
     */
    public PacketData getPacketData() {
        PacketType type = getType();
        if (type == null) return null;
        return null;
        // TODO: this
    }

    /**
     * Sets the packet payload.
     *
     * @param payload The packet payload.
     * @return This instance of Packet.
     */
    public Packet setPacketData(PacketData payload) {
        if (payload == null) return this;
        int copyLen = Math.min(data.length - 32 - getPacketDataStartIndex(), payload.getSize());
        ByteBufferOverwriteOutputStream ovrw = new ByteBufferOverwriteOutputStream(data, getPacketDataStartIndex(), copyLen);
        try {
            payload.getData().transferTo(ovrw);
        } catch (IOException e) {
        }
        if (isEncrypted()) data[1] = getType().getID();
        return this;
    }

    /**
     * Gets the payload start index in the packet.
     *
     * @return The payload start index.
     */
    public int getPacketDataStartIndex() {
        return 12;
    }

    /**
     * Gets the TTL for the packet.
     *
     * @return The number of hops remaining / 255 for infinite.
     */
    public byte getTTL() {
        if (data == null || data.length < 1) return (byte) 255;
        return data[0];
    }

    /**
     * Sets the TTL for the packet.
     *
     * @param ttl The number of hops remaining / 255 for infinite.
     * @return This instance of Packet.
     */
    public Packet setTTL(byte ttl) {
        if (data == null || data.length < 1) return this;
        data[0] = ttl;
        return this;
    }

    /**
     * Encrypts the packet.
     *
     * @param cProvider The {@link ICryptor} to use.
     * @return This instance of Packet.
     * @throws GeneralSecurityException A security cryptographic has occurred.
     */
    public Packet Encrypt(ICryptor cProvider) throws GeneralSecurityException {
        if (!isEncrypted())
            data[1] = getType().getEncryptedID();
        return this;
    }

    /**
     * Decrypts the packet.
     *
     * @param cProvider The {@link ICryptor} to use.
     * @return This instance of Packet.
     * @throws GeneralSecurityException A security cryptographic has occurred.
     */
    public Packet Decrypt(ICryptor cProvider) throws GeneralSecurityException {
        if (isEncrypted())
            data[1] = getType().getID();
        return this;
    }

    /**
     * Gets the size of the payload.
     *
     * @return The size of the payload.
     */
    public int getPayloadSize() {
        if (length == null)
            length = (short) (data[2] * 256 + data[3]);
        return length;
    }

    /**
     * Gets the size of the packet.
     *
     * @return The size of the packet.
     */
    public int getPacketSize() {
        if (length == null)
            return 0;
        return data.length;
    }

    /**
     * Gets the timestamp of the packet.
     *
     * @return The packet timestamp.
     */
    public long getTimeStamp() {
        if (timeStamp == null) {
            try {
                timeStamp = IntOnStream.ReadLong(new ByteArrayInputStream(data, 4, 8));
            } catch (IOException ignored) {
            }
        }
        return timeStamp;
    }

    /**
     * Timestamps the packet with the current 10-minute epoch period.
     *
     * @return This instance of Packet.
     */
    public Packet timeStamp() {
        timeStamp = Instant.now().getEpochSecond() / 600; // Current 10 Mins ts
        timeStamp *= 600;
        try {
            IntOnStream.WriteLong(new ByteBufferOverwriteOutputStream(data, 4, 8), timeStamp);
        } catch (IOException ignored) {
        }
        return this;
    }

    /**
     * Checks if the packet timestamp is within the current, previous or next 10-minute epoch window.
     *
     * @return If the timestamp is in range.
     */
    public boolean timeStampInRange() {
        long cTime = Instant.now().getEpochSecond() / 600;
        cTime *= 600;
        long cTS = getTimeStamp();
        return  cTS == cTime || cTS == cTime - 600 || cTS == cTime + 600;
    }

    /**
     * Verifies the hash of the packet.
     *
     * @param hProvider The {@link IHasher} to use.
     * @return If the hash matches.
     */
    public boolean verifyHash(IHasher hProvider) {
        try {
            int pkhsz = getPacketDataStartIndex() + getPayloadSize();
            return StreamEquals.streamEquals(new ByteArrayInputStream(data, pkhsz, 32),
                    new ByteArrayInputStream(hProvider.hashStream(new ByteArrayInputStream(data, 1, pkhsz - 1), pkhsz - 1)));
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Verifies the packet hash and provided signature.
     *
     * @param hProvider The {@link IHasher} to use.
     * @param vProvider The {@link IVerifier} to use.
     * @param signature The signature that corresponds to the packet's hash.
     * @return If the signature was verified successfully.
     */
    public boolean verifySignature(IHasher hProvider, IVerifier vProvider, byte[] signature) {
        if (!verifyHash(hProvider)) return false;
        try {
            return vProvider.verify(new ByteArrayInputStream(data, getPacketDataStartIndex() + getPayloadSize(), 32), signature);
        } catch (GeneralSecurityException | IOException e) {
            return false;
        }
    }

    /**
     * Validates the packet.
     *
     * @param hProvider The {@link IHasher} to use.
     * @return If the packet is valid.
     */
    public boolean validate(IHasher hProvider) {
        if (!timeStampInRange()) return false;
        return verifyHash(hProvider);
    }

    /**
     * Validates the packet.
     *
     * @param hProvider The {@link IHasher} to use.
     * @param vProvider The {@link IVerifier} to use.
     * @param signature The signature that corresponds to the packet's hash.
     * @return If the packet is valid.
     */
    public boolean validateWithSignature(IHasher hProvider, IVerifier vProvider, byte[] signature) {
        if (!timeStampInRange()) return false;
        return verifySignature(hProvider, vProvider, signature);
    }

    /**
     * Recalculates the hash of the packet.
     *
     * @param hProvider The {@link IHasher} to use.
     * @return This instance of Packet.
     */
    public Packet calculateHash(IHasher hProvider) {
        if (data == null || data.length < 34) return this;
        int pkhsz = getPacketDataStartIndex() + getPayloadSize();
        ByteBufferOverwriteOutputStream ovrw = new ByteBufferOverwriteOutputStream(data, pkhsz, 32);
        try {
            ovrw.write(hProvider.hashStream(new ByteArrayInputStream(data, 1, pkhsz - 1), pkhsz - 1));
        } catch (IOException ignored) {
        }
        return this;
    }

    /**
     * Gets the signature packet's for this packet.
     * These packets are not hashed nor encrypted, this must be processed, before being sent, by the caller.
     *
     * @param hProvider The {@link IHasher} to use.
     * @param sProvider The {@link ISigner} to use.
     * @param splitSize The maximum size of a signature fragment (Not the packet or payload size).
     * @return An array of signature packets.
     * @throws GeneralSecurityException A cryptographic error ahs occurred.
     */
    public Packet[] getSignaturePackets(IHasher hProvider, ISigner sProvider, int splitSize) throws GeneralSecurityException {
        calculateHash(hProvider);
        byte[] hash = new byte[32];
        System.arraycopy(data, getPacketDataStartIndex() + getPayloadSize(), hash, 0, 32);
        SignaturePayload[] sPayloads = SignaturePayload.getFragmentedSignature(sProvider.sign(hash), hash, hProvider, splitSize);
        Packet[] toReturn = new Packet[sPayloads.length];
        byte[] sAddr = null;
        byte[] dAddr = null;
        PacketMessagingType mT = getType().getMessagingType();
        if (mT == PacketMessagingType.Broadcast) {
            sAddr = ((BroadcastPacket) this).getSourceAddress();
        } else if (mT == PacketMessagingType.Unicast) {
            sAddr = ((UnicastPacket) this).getSourceAddress();
            dAddr = ((UnicastPacket) this).getDestinationAddress();
        }
        for (int i = 0; i < sPayloads.length; i++) {
            switch (mT) {
                case Direct -> {
                    toReturn[i] = new Packet(Packet.MIN_SIZE + sPayloads[i].getSize()).
                            setPacketType(PacketType.DirectSignature).setTTL(
                                    (byte) 0).setPacketData(sPayloads[i]).timeStamp();
                }
                case Broadcast -> {
                    toReturn[i] = new BroadcastPacket(BroadcastPacket.MIN_SIZE + sPayloads[i].getSize()).setSourceAddress(sAddr).
                            setPacketType(PacketType.BroadcastSignature).setTTL(
                                    (byte) 254).setPacketData(sPayloads[i]).timeStamp();
                }
                case Unicast -> {
                    toReturn[i] = new UnicastPacket(UnicastPacket.MIN_SIZE + sPayloads[i].getSize()).setDestinationAddress(dAddr).setSourceAddress(sAddr).
                            setPacketType(PacketType.UnicastSignature).setTTL(
                                    (byte) 254).setPacketData(sPayloads[i]).timeStamp();
                }
            }
        }
        return toReturn;
    }
}
