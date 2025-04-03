package com.captainalm.lib.mesh.packets;

import com.captainalm.lib.mesh.crypto.ICryptor;
import com.captainalm.lib.mesh.utils.ByteBufferOverwriteOutputStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Provides a unicast packet representation which has a
 * destination address and IV used for symmetric encryption.
 *
 * @author Alfred Manville
 */
public class UnicastPacket extends BroadcastPacket {
    public static final int MIN_SIZE = 124;

    protected UnicastPacket(byte[] packet) {
        super(packet);
    }

    /**
     * Creates a unicast new packet with a specified payload size.
     *
     * @param size The size of the payload.
     */
    public UnicastPacket(int size) {
        super(size);
    }

    /**
     * Gets the payload start index in the packet.
     *
     * @return The payload start index.
     */
    @Override
    public int getPacketDataStartIndex() {
        return super.getPacketDataStartIndex() + 48;
    }

    /**
     * Gets the destination address of the packet.
     *
     * @return The destination address.
     */
    public byte[] getDestinationAddress() {
        byte[] addr = new byte[32];
        if (data == null || data.length < 124) return addr;
        System.arraycopy(data, 44, addr, 0, 32);
        return addr;
    }

    /**
     * Sets the destination address of the packet.
     *
     * @param addr The destination address.
     * @return This instance of Packet.
     */
    public UnicastPacket setDestinationAddress(byte[] addr) {
        if (addr == null || addr.length != 32 || data == null || data.length < 124) return this;
        System.arraycopy(addr, 0, data, 44, 32);
        return this;
    }

    /**
     * Encrypts the packet.
     *
     * @param cProvider The {@link ICryptor} to use.
     * @return This instance of Packet.
     */
    @Override
    public Packet Encrypt(ICryptor cProvider) throws GeneralSecurityException {
        if (!isEncrypted()) {
            try {
                cProvider.encryptStream(new ByteArrayInputStream(data, getPacketDataStartIndex(), getPayloadSize()),
                        new ByteBufferOverwriteOutputStream(data, getPacketDataStartIndex() - 16, getPayloadSize() + 16));
                return super.Encrypt(cProvider);
            } catch (IOException ignored) {
                return this;
            }
        }
        return this;
    }

    /**
     * Decrypts the packet.
     *
     * @param cProvider The {@link ICryptor} to use.
     * @return This instance of Packet.
     * @throws GeneralSecurityException A security cryptographic has occurred.
     */
    @Override
    public Packet Decrypt(ICryptor cProvider) throws GeneralSecurityException {
        if (isEncrypted()) {
            try {
                cProvider.decryptStream(new ByteArrayInputStream(data, getPacketDataStartIndex() - 16, getPayloadSize() + 16),
                        new ByteBufferOverwriteOutputStream(data, getPacketDataStartIndex(), getPayloadSize()));
            } catch (IOException ignored) {
                return this;
            }
            return super.Decrypt(cProvider);
        }
        return this;
    }
}
