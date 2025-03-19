package com.captainalm.lib.mesh.crypto;

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
     */
    void setPublicKey(byte[] key);

    /**
     * Verifies the data given the signature using the {@link #getPublicKey()}.
     *
     * @param data The data to verify.
     * @param signature The signature to check.
     * @return If the data was verified successfully.
     * @throws GeneralSecurityException A verification issue has occurred.
     */
    boolean verify(byte[] data, byte[] signature) throws GeneralSecurityException   ;
}
