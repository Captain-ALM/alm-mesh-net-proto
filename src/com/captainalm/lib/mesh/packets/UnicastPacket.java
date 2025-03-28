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

    /**
     * Creates a unicast packet from its data representation.
     *
     * @param packet The packet data.
     */
    public UnicastPacket(byte[] packet) {
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

    @Override
    protected int getPacketDataStartIndex() {
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
     */
    public void setDestinationAddress(byte[] addr) {
        if (addr == null || addr.length != 32 || data == null || data.length < 124) return;
        System.arraycopy(addr, 0, data, 44, 32);
    }
    /**
     * Gets the IV of the packet for encryption.
     *
     * @return The IV.
     */
    public byte[] getIV() {
        byte[] iv = new byte[16];
        if (data == null || data.length < 124) return iv;
        System.arraycopy(data, 76, iv, 0, 16);
        return iv;
    }

    /**
     * Sets the IV of the packet for encryption.
     *
     * @param iv The IV.
     */
    public void setIV(byte[] iv) {
        if (iv == null || iv.length != 16 || data == null || data.length < 124) return;
        System.arraycopy(iv, 0, data, 76, 16);
    }

    /**
     * Encrypts the packet.
     *
     * @param cProvider The {@link ICryptor} to use.
     * @return If the encryption succeeded.
     */
    @Override
    public boolean Encrypt(ICryptor cProvider) {
        if (!isEncrypted()) {
            try {
                cProvider.encryptStream(new ByteArrayInputStream(data, getPacketDataStartIndex(), getPayloadSize()),
                        new ByteBufferOverwriteOutputStream(data, getPacketDataStartIndex() - 16, getPayloadSize() + 16));
                return super.Encrypt(cProvider);
            } catch (IOException | GeneralSecurityException ignored) {
                return false;
            }
        }
        return true;
    }

    /**
     * Decrypts the packet.
     *
     * @param cProvider The {@link ICryptor} to use.
     * @return If the decryption succeeded.
     */
    @Override
    public boolean Decrypt(ICryptor cProvider) {
        if (isEncrypted()) {
            try {
                cProvider.decryptStream(new ByteArrayInputStream(data, getPacketDataStartIndex() - 16, getPayloadSize() + 16),
                        new ByteBufferOverwriteOutputStream(data, getPacketDataStartIndex(), getPayloadSize()));
            } catch (IOException | GeneralSecurityException ignored) {
                return false;
            }
            return super.Decrypt(cProvider);
        }
        return true;
    }
}
