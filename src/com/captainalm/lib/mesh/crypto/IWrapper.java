package com.captainalm.lib.mesh.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Random;

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
     * produces a shared secret and cipher text using the {@link #getPublicKey()}.
     *
     * @param rand {@link java.security.SecureRandom} for key generation.
     * @return An array with the shared secret [0] and the wrapped key data [1].
     * @throws GeneralSecurityException A wrapping issue has occurred.
     */
    byte[][] wrap(SecureRandom rand) throws GeneralSecurityException;
}
