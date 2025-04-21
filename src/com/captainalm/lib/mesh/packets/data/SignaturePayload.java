package com.captainalm.lib.mesh.packets.data;

import com.captainalm.lib.mesh.crypto.IHasher;
import com.captainalm.lib.mesh.packets.Packet;
import com.captainalm.lib.mesh.utils.ByteBufferOverwriteOutputStream;
import com.captainalm.lib.mesh.utils.BytesToHex;
import com.captainalm.lib.mesh.utils.InputStreamTransfer;
import com.captainalm.lib.mesh.utils.IntOnStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

/**
 * Provides a payload for signature packets.
 * {@link com.captainalm.lib.mesh.packets.PacketType#DirectSignature}
 * {@link com.captainalm.lib.mesh.packets.PacketType#DirectHandshakeIDSignature}
 * {@link com.captainalm.lib.mesh.packets.PacketType#DirectHandshakeDSARecommendationSignature}
 * {@link com.captainalm.lib.mesh.packets.PacketType#BroadcastSignature}
 * {@link com.captainalm.lib.mesh.packets.PacketType#UnicastSignature}
 * {@link com.captainalm.lib.mesh.packets.PacketType#DirectHandshakeSignature}
 *
 * @author Alfred Manville
 */
public class SignaturePayload extends PacketData {
    protected String dataHashString;
    protected Integer signatureLength;

    /**
     * Constructs a new instance of a SignaturePayload from a {@link Packet}.
     *
     * @param packet The packet to construct from.
     */
    public SignaturePayload(Packet packet) {
        super(packet);
    }

    /**
     * Constructs a new instance of SignaturePayload with the specified signature portion.
     *
     * @param signaturePart the partial or complete signature.
     * @param partID The ID of the fragment part.
     * @param maxParts The number of fragments this signature has.
     * @param dataHash The hash that is signed by the signature.
     * @param signatureHash The hash of the full signature.
     * @param signatureLength The length of the full signature.
     * @throws IllegalArgumentException dataHash or signatureHash are null.
     */
    public SignaturePayload(byte[] signaturePart, byte partID, byte maxParts, byte[] dataHash, byte[] signatureHash, int signatureLength) {
        super(66 + ((signaturePart == null) ? 0 : signaturePart.length + 4));
        this.data[0] = partID;
        this.data[1] = maxParts;
        if (signatureHash == null)
            throw new IllegalArgumentException("signatureHash is null");
        System.arraycopy(signatureHash, 0, this.data, 2, 32);
        if (dataHash == null)
            throw new IllegalArgumentException("dataHash is null");
        System.arraycopy(dataHash, 0, this.data, 34, 32);
        if (signaturePart != null) {
            ByteBufferOverwriteOutputStream ovrw = new ByteBufferOverwriteOutputStream(this.data, 66, 4);
            try {
                IntOnStream.WriteInt(ovrw, signatureLength);
            } catch (IOException ignored) {
            }
            this.signatureLength = signatureLength;
            System.arraycopy(signaturePart, 0, this.data, 70, signaturePart.length);
        }
        dataHashString = BytesToHex.bytesToHex(dataHash);
    }

    /**
     * Gets the fragment ID.
     *
     * @return The fragment ID.
     */
    public byte getPartID() {
        return data[this.dataStartIndex];
    }

    /**
     * Gets the number of fragments that make this signature.
     *
     * @return The number of fragments.
     */
    public byte getMaxParts() {
        return data[this.dataStartIndex + 1];
    }

    /**
     * Gets the data hash.
     *
     * @return The data hash as an {@link ByteArrayInputStream}.
     */
    public ByteArrayInputStream getDataHash() {
        return new ByteArrayInputStream(data, this.dataStartIndex + 34, 32);
    }

    /**
     * Gets the signature hash.
     *
     * @return The signature hash as an {@link ByteArrayInputStream}.
     */
    public ByteArrayInputStream getSignatureHash() {
        return new ByteArrayInputStream(data, this.dataStartIndex + 2, 32);
    }

    /**
     * Gets the data hash as a hexadecimal string.
     *
     * @return The data hash hexadecimal string.
     */
    public String getDataHashString() {
        if (dataHashString == null) {
            try {
                dataHashString = BytesToHex.bytesToHexFromStreamWithSize(getDataHash(), 32);
            } catch (IOException ignored) {
            }
        }
        return dataHashString;
    }

    /**
     * Gets the full length of the signature.
     *
     * @return The length of the signature.
     */
    public int getSignatureLength() {
        if (signatureLength == null) {
            ByteArrayInputStream rdr = new ByteArrayInputStream(data, this.dataStartIndex + 66, 4);
            try {
                signatureLength = IntOnStream.ReadInt(rdr);
            } catch (IOException ignored) {
            }
        }
        return signatureLength;
    }

    /**
     * Writes the contained signature fragment to the passed {@link OutputStream}.
     *
     * @param out The output stream to write to.
     */
    public void writeSignatureFragment(OutputStream out) {
        try {
            InputStreamTransfer.streamTransfer(new ByteArrayInputStream(data, this.dataStartIndex + 70, dataSize - 70), out);
        } catch (IOException ignored) {
        }
    }

    /**
     * Gets the {@link SignaturePayload} fragments giving a split length.
     *
     * @param signature The signature to store.
     * @param dataHash The hash that is signed by the signature.
     * @param hProvider The hash provider.
     * @param splitSize The size of the split data.
     * @return The fragmented signature array.
     */
    public static SignaturePayload[] getFragmentedSignature(byte[] signature, byte[] dataHash, IHasher hProvider, int splitSize) {
        byte[] signatureHash = hProvider.hash(signature);
        int fullFragmentCount = signature.length / splitSize;
        SignaturePayload[] fragments = new SignaturePayload[fullFragmentCount + (signature.length % splitSize == 0 ? 0 : 1)];
        for (int i = 0; i < fullFragmentCount; i++) {
            byte[] part = new byte[splitSize];
            System.arraycopy(signature, i * splitSize, part, 0, splitSize);
            fragments[i] = new SignaturePayload(part, (byte) i, (byte) fragments.length, dataHash, signatureHash, signature.length);
        }
        if (fragments.length > fullFragmentCount) {
            byte[] part = new byte[signature.length%splitSize];
            System.arraycopy(signature, fullFragmentCount * splitSize, part, 0, splitSize);
            fragments[fullFragmentCount] = new SignaturePayload(part, (byte) fullFragmentCount, (byte) fragments.length, dataHash, signatureHash, signature.length);
        }
        return fragments;
    }

    /**
     * Gets the signature given the {@link SignaturePayload}s IN ORDER.
     *
     * @param fragments The signature payloads.
     * @param signatureHash The hash of the signature.
     * @param hProvider The hash provider to validate the assembled signature with.
     * @return The signature or an empty byte array on validation failure.
     */
    public static byte[] getSignatureFromFragments(SignaturePayload[] fragments, byte[] signatureHash, IHasher hProvider) {
        byte[] signature = new byte[fragments[0].getSignatureLength()];
        OutputStream out = new ByteBufferOverwriteOutputStream(signature, 0, signature.length);
        for (SignaturePayload fragment : fragments)
            if (fragment == null)
                return new byte[0];
            else
                fragment.writeSignatureFragment(out);
        byte[] cHash =  hProvider.hash(signature);
        if (!Arrays.equals(cHash, signatureHash))
            return new byte[0];
        return signature;
    }
}
