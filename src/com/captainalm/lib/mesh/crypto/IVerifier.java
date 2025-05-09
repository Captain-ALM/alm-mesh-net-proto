package com.captainalm.lib.mesh.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/**
 * Provides a data verifier.
 *
 * @author Alfred Manville
 */
public interface IVerifier {
    /**
     * Gets the public key of the verifier.
     *
     * @return The public key.
     */
    byte[] getPublicKey();

    /**
     * Sets the public key for verifying.
     *
     * @param key The new public key.
     * @return This iverifier instance.
     */
    IVerifier setPublicKey(byte[] key);

    /**
     * Verifies the data given the signature using the {@link #getPublicKey()}.
     *
     * @param data The data to verify.
     * @param signature The signature to check.
     * @return If the data was verified successfully.
     * @throws GeneralSecurityException A verification issue has occurred.
     */
    boolean verify(byte[] data, byte[] signature) throws GeneralSecurityException;

    /**
     * Verifies the data from the passed {@link InputStream}
     * given the signature using the {@link #getPublicKey()}.
     *
     * @param input The {@link InputStream}.
     * @param signature The signature to check.
     * @return If the data was verified successfully.
     * @throws GeneralSecurityException A verification issue has occurred.
     * @throws IOException An I/O Error has occurred.
     */
    boolean verify(InputStream input, byte[] signature) throws GeneralSecurityException, IOException;
}
