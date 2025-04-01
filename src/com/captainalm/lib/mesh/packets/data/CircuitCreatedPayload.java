package com.captainalm.lib.mesh.packets.data;

import com.captainalm.lib.mesh.packets.Packet;
import com.captainalm.lib.mesh.utils.ByteBufferOverwriteOutputStream;
import com.captainalm.lib.mesh.utils.BytesToHex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Provides a payload to signify a successful onion circuit creation.
 * {@link com.captainalm.lib.mesh.packets.PacketType#UnicastOnionCircuitCreated}
 *
 * @author Alfred Manville
 */
public class CircuitCreatedPayload extends PacketData implements INonce {
    protected byte[] encryptedKey;
    protected byte[] circuitID;
    protected String strCircuitID;

    /**
     * Constructs a new instance of CircuitCreatedPayload from a {@link Packet}.
     *
     * @param packet The packet to construct from.
     */
    public CircuitCreatedPayload(Packet packet) {
        super(packet);
    }

    /**
     * Constructs a new instance of CircuitCreatedPayload with a nonce, circuit ID and encrypted circuit key.
     *
     * @param nonce The nonce input stream.
     * @param circuitID The ID of the circuit.
     * @param encryptedKey The encrypted circuit key.
     */
    public CircuitCreatedPayload(InputStream nonce, byte[] circuitID, byte[] encryptedKey) {
        super((nonce == null || circuitID == null || circuitID.length != 16 || encryptedKey == null || encryptedKey.length != 32) ? 0 : 64);
        if (dataSize > 0) {
            this.encryptedKey = encryptedKey;
            this.circuitID = circuitID;
            this.strCircuitID = BytesToHex.bytesToHex(circuitID);
            try {
                nonce.transferTo(new ByteBufferOverwriteOutputStream(data, 0, 16));
            } catch (IOException ignored) {
            }
            System.arraycopy(circuitID, 0, data, 16, 16);
            System.arraycopy(encryptedKey, 0, data, 32, 32);
        }
    }

    /**
     * Gets the nonce in stream form.
     *
     * @return The nonce stream.
     */
    @Override
    public ByteArrayInputStream getNonceStream() {
        return new ByteArrayInputStream(data, dataStartIndex, 16);
    }

    /**
     * Gets the onion circuit ID.
     *
     * @return The circuit ID.
     */
    public byte[] getCircuitID() {
        if (circuitID == null && dataSize == 64) {
            circuitID = new byte[16];
            System.arraycopy(data, dataStartIndex + 16, circuitID, 0, 16);
        }
        return circuitID;
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
     * Gets the encrypted circuit key.
     *
     * @return The encrypted key.
     */
    public byte[] getEncryptedKey() {
        if (encryptedKey == null && dataSize == 64) {
            encryptedKey = new byte[32];
            System.arraycopy(data, dataStartIndex + 32, encryptedKey, 0, 32);
        }
        return encryptedKey;
    }
}
