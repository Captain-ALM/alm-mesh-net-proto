package com.captainalm.lib.mesh.crypto;

import java.security.GeneralSecurityException;

/**
 * Provides a key wrapper.
 *
 * @author Alfred Manville
 */
public interface IWrapper {
    /**
     * Gets the public key of the wrapper.
     *
     * @return The public key.
     */
    byte[] getPublicKey();

    /**
     * Sets the public key for wrapping.
     *
     * @param key The new public key.
     * @return This iwrapper instance.
     */
    IWrapper setPublicKey(byte[] key);

    /**
     * Wraps the passed key given the signature using the {@link #getPublicKey()}.
     *
     * @param keyData The key to wrap.
     * @return The wrapped key data.
     * @throws GeneralSecurityException A wrapping issue has occurred.
     */
    byte[] wrap(byte[] keyData) throws GeneralSecurityException   ;
}
