package com.captainalm.lib.mesh.crypto;

import java.security.GeneralSecurityException;

/**
 * Provides a key un-wrapper.
 *
 * @author Alfred Manville
 */
public interface IUnwrapper extends IWrapper {
    /**
     * Gets the private key of the wrapper.
     *
     * @return The private key.
     */
    byte[] getPrivateKey();

    /**
     * Sets the private key for un-wrapping.
     *
     * @param key The new private key.
     */
    void setPrivateKey(byte[] key);
    /**
     * Unwraps the passed data using the {@link #getPrivateKey()}.
     *
     * @param data The data to un-wrap.
     * @return The unwrapped key.
     * @throws GeneralSecurityException An unwrapping issue has occurred.
     */
    byte[] unwrap(byte[] data) throws GeneralSecurityException;
}
