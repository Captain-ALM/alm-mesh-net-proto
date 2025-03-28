package com.captainalm.lib.mesh.crypto;

/**
 * Provides cryptography provider instances.
 *
 * @author Alfred Manville
 */
public interface IProvider {
    /**
     * Provides symmetric cryptography expecting/providing the IV in the data stream.
     */

    ICryptor GetCryptorInstance();
    /**
     * Provides symmetric cryptography with the IV provided as part of the key.
     */
    ICryptor GetFixedIVCryptorInstance();

    /**
     * Provides hashing.
     */
    IHasher GetHasherInstance();

    /**
     * Provides a signer.
     */
    ISigner GetSignerInstance();

    /**
     * Provides a key un-wrapper.
     */
    IUnwrapper GetUnwrapperInstance();

    /**
     * Provides a signature verifier.
     */
    IVerifier GetVerifierInstance();

    /**
     * Provides a key wrapper.
     */
    IWrapper GetWrapperInstance();
}
