package com.captainalm.lib.mesh.crypto;

import java.security.GeneralSecurityException;

/**
 * Provides a data signer.
 *
 * @author Alfred Manville
 */
public interface ISigner extends IVerifier {
    /**
     * Gets the private key of the signer.
     *
     * @return The private key.
     */
    byte[] getPrivateKey();

    /**
     * Sets the private key for signing.
     *
     * @param key The new private key.
     */
    void setPrivateKey(byte[] key);

    /**
     * Signs the passed data using the {@link #getPrivateKey()}.
     *
     * @param data The data to sign.
     * @return The signed data.
     * @throws GeneralSecurityException A signing issue has occurred.
     */
    byte[] sign(byte[] data) throws GeneralSecurityException;
}
