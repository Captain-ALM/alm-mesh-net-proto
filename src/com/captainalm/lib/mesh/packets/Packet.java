package com.captainalm.lib.mesh.packets;

import com.captainalm.lib.mesh.crypto.ICryptor;
import com.captainalm.lib.mesh.crypto.IHasher;
import com.captainalm.lib.mesh.crypto.IVerifier;
import com.captainalm.lib.mesh.packets.data.IPacketData;
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

    /**
     * Creates a new packet with a specified payload size.
     *
     * @param size The size of the payload.
     */
    public Packet(int size) {
        this.data = new byte[getPacketDataStartIndex() + size + 32];
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
     */
    public void setPacketType(PacketType type) {
        if (data == null || data.length < 2) return;
        data[1] = type.getID();
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
    public IPacketData getPacketData() {
        PacketType type = getType();
        if (type == null) return null;
        return null;
        // TODO: this
    }

    /**
     * Sets the packet payload.
     *
     * @param payload The packet payload.
     */
    public void setPacketData(IPacketData payload) {
        if (payload == null) return;
        int copyLen = Math.min(data.length - 32 - getPacketDataStartIndex(), payload.getPacketLength());
        ByteBufferOverwriteOutputStream ovrw = new ByteBufferOverwriteOutputStream(data, getPacketDataStartIndex(), copyLen);
        try {
            ovrw.write(payload.getPacketPayload(), getPacketDataStartIndex(), copyLen );
        } catch (IOException e) {
        }
        if (isEncrypted()) data[1] = getType().getID();

    }

    protected int getPacketDataStartIndex() {
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
     */
    public void setTTL(byte ttl) {
        if (data == null || data.length < 1) return;
        data[0] = ttl;
    }

    /**
     * Encrypts the packet.
     *
     * @param cProvider The {@link ICryptor} to use.
     * @return If the encryption succeeded.
     */
    public boolean Encrypt(ICryptor cProvider) {
        if (!isEncrypted())
            data[1] = getType().getEncryptedID();
        return true;
    }

    /**
     * Decrypts the packet.
     *
     * @param cProvider The {@link ICryptor} to use.
     * @return If the decryption succeeded.
     */
    public boolean Decrypt(ICryptor cProvider) {
        if (isEncrypted())
            data[1] = getType().getID();
        return true;
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
     */
    public void timeStamp() {
        timeStamp = Instant.now().getEpochSecond() / 600; // Current 10 Mins ts
        timeStamp *= 600;
        try {
            IntOnStream.WriteLong(new ByteBufferOverwriteOutputStream(data, 4, 8), timeStamp);
        } catch (IOException ignored) {
        }
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
            return StreamEquals.streamEquals(new ByteArrayInputStream(data, getPacketDataStartIndex() + getPayloadSize(), 32),
                    new ByteArrayInputStream(hProvider.hashStream(new ByteArrayInputStream(data, 1, data.length - 33), data.length - 33)));
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
     */
    public void calculateHash(IHasher hProvider) {
        if (data == null || data.length < 34) return;
        ByteBufferOverwriteOutputStream ovrw = new ByteBufferOverwriteOutputStream(data, getPacketDataStartIndex() + getPayloadSize(), 32);
        try {
            ovrw.write(hProvider.hashStream(new ByteArrayInputStream(data, 1, data.length - 33), data.length - 33));
        } catch (IOException ignored) {
        }
    }
}
