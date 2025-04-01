package com.captainalm.lib.mesh.packets.layer;

import com.captainalm.lib.mesh.crypto.ICryptor;
import com.captainalm.lib.mesh.packets.PacketType;
import com.captainalm.lib.mesh.utils.ByteBufferOverwriteOutputStream;
import com.captainalm.lib.mesh.utils.BytesToHex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Provides an OnionLayer.
 *
 * @author Alfred Manville
 */
public class OnionLayer {
    protected byte[] data;
    protected int dataStartIndex;
    protected int dataSize;
    protected OnionLayer subLayer;
    protected OnionLayer parent;
    protected String strCircuitID;

    /**
     * Creates a new OnionLayer from existing data.
     *
     * @param data The data buffer.
     * @param dataStartIndex The start index of the layer.
     * @param dataSize The size of the layer.
     */
    public OnionLayer(byte[] data, int dataStartIndex, int dataSize) {
        this.data = data;
        this.dataStartIndex = dataStartIndex;
        this.dataSize = dataSize;
    }

    /**
     * Creates a new OnionLayer containing another layer.
     *
     * @param encapsulatedLayer The layer to encapsulate.
     * @throws IllegalArgumentException The encapsulated layer already has a parent.
     */
    public OnionLayer(OnionLayer encapsulatedLayer) {
        if (encapsulatedLayer.parent != null)
            throw new IllegalArgumentException("encapsulatedLayer already has a parent");
        this.data = new byte[encapsulatedLayer.dataSize + 33];
        this.dataStartIndex = 0;
        this.dataSize = this.data.length;
        this.subLayer = encapsulatedLayer;
        System.arraycopy(encapsulatedLayer.data, encapsulatedLayer.dataStartIndex, data, 0, encapsulatedLayer.dataSize);
        this.subLayer.parent = this;
        this.subLayer.data = this.data;
        this.subLayer.dataStartIndex += 33;
        this.data[0] = PacketType.UnicastOnion.getID();
    }

    /**
     * Gets the onion circuit ID.
     *
     * @return The circuit ID.
     */
    public byte[] getCircuitID() {
        byte[] id = new byte[16];
        if (data == null || dataSize < 33) return id;
        System.arraycopy(data, dataStartIndex + 1, id, 0, 16);
        return id;
    }

    /**
     * Gets the onion circuit ID as a hexadecimal string.
     *
     * @return The circuit ID hexadecimal string.
     */
    public String getCircuitIDString() {
        if (strCircuitID == null)
            strCircuitID = BytesToHex.bytesToHex(getCircuitID());
        return strCircuitID;
    }

    /**
     * Sets the onion circuit ID.
     *
     * @param id The circuit ID.
     * @return This instance of OnionLayer.
     */
    public OnionLayer setCircuitID(byte[] id) {
        if (id == null || id.length != 16 || data == null || dataSize < 33) return this;
        System.arraycopy(id, 0, data, dataStartIndex + 1, 16);
        return this;
    }

    /**
     * Gets if the layer has been encrypted.
     *
     * @return If the layer is encrypted.
     */
    public boolean isEncrypted() {
        if (data == null || dataSize < 17) return false;
        return data[dataStartIndex + 17] != 0;
    }

    /**
     * Encrypts this layer given the {@link ICryptor} provider.
     *
     * @param cProvider The symmetric encryptor.
     * @return This instance of OnionLayer.
     * @throws GeneralSecurityException A cryptographic exception has occurred.
     */
    public OnionLayer encrypt(ICryptor cProvider) throws GeneralSecurityException {
        if (subLayer == null || subLayer.isEncrypted()) {
            if (!isEncrypted()) {
                try {
                    cProvider.encryptStream(new ByteArrayInputStream(data, dataStartIndex + 33, dataSize - 33),
                            new ByteBufferOverwriteOutputStream(data, dataStartIndex + 17, dataSize - 17));
                } catch (IOException ignored) {
                    return this;
                }
            }
        }
        return this;
    }

    /**
     * Decrypts this layer given the {@link ICryptor} provider.
     *
     * @param cProvider The symmetric decryptor.
     * @return This instance of OnionLayer.
     * @throws GeneralSecurityException A cryptographic exception has occurred.
     */
    public OnionLayer decrypt(ICryptor cProvider) throws GeneralSecurityException {
        if (isEncrypted()) {
            try {
                cProvider.decryptStream(new ByteArrayInputStream(data, dataStartIndex + 17, dataSize - 17),
                        new ByteBufferOverwriteOutputStream(data, dataStartIndex + 33, dataSize - 33));
            } catch (IOException ignored) {
                return this;
            }
        }
        return this;
    }

    /**
     * Encrypts this layer and all the sub-layers starting from the bottom and going up.
     *
     * @param cProviders The symmetric encryptors for each layer, the order is the bottom layer uses the first provider.
     * @return This instance of OnionLayer.
     * @throws GeneralSecurityException A cryptographic exception has occurred.
     */
    public OnionLayer encryptAll(ICryptor[] cProviders) throws GeneralSecurityException {
        encryptAll(cProviders, cProviders.length - 1);
        return this;
    }

    protected void encryptAll(ICryptor[] cProviders, int idx) throws GeneralSecurityException {
        if (idx > 0) getSubLayer().encryptAll(cProviders, idx - 1);
        encrypt(cProviders[idx]);
    }

    /**
     * Gets the size of the layer.
     *
     * @return The size of the layer.
     */
    public int getSize() {
        return dataSize;
    }

    /**
     * Gets the sub-layer.
     * null if still {@link #isEncrypted()}.
     *
     * @return The sub-layer or null.
     */
    public OnionLayer getSubLayer() {
        if (subLayer == null && dataSize - 33 > 32 && !isEncrypted()) {
            if (data[dataStartIndex + 33] == PacketType.UnicastOnion.getID())
                subLayer = new OnionLayer(data, dataStartIndex + 33, dataSize - 33);
            else
                subLayer = new DataLayer(data, dataStartIndex + 33, dataSize - 33);

        }
        return subLayer;
    }

    /**
     * Gets the parent layer.
     *
     * @return The parent layer or null.
     */
    public OnionLayer getParent() {
        return parent;
    }
}
