package com.captainalm.lib.mesh.crypto;

import java.io.IOException;
import java.io.InputStream;
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

    /**
     * Signs the data from the passed {@link InputStream}
     * using the {@link #getPrivateKey()}.
     *
     * @param input The {@link InputStream}.
     * @return The signed data.
     * @throws GeneralSecurityException A signing issue has occurred.
     * @throws IOException An I/O Error has occurred.
     */
    byte[] sign(InputStream input) throws GeneralSecurityException, IOException;
}
