package com.captainalm.lib.mesh.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

/**
 * Provides a generic symmetric encryption interface.
 *
 * @author Alfred Manville
 */
public interface ICryptor {
    /**
     * Sets the symmetric key.
     *
     * @param key The secret key.
     */
    void setKey(byte[] key);

    /**
     * Gets the symmetric key.
     *
     * @return The secret key.
     */
    byte[] getKey();

    /**
     * Encrypts to a stream using {@link #getKey()} symmetric key.
     *
     * @param data The data to encrypt.
     * @param out The {@link OutputStream}.
     * @return The number of bytes written.
     * @throws IOException  A Stream I/O Issue occurred.
     * @throws GeneralSecurityException A Crypto Error Occurred.
     */
    int encryptToStream(byte[] data, OutputStream out) throws IOException, GeneralSecurityException;
    /**
     * Encrypts data using {@link #getKey()} symmetric key.
     *
     * @param data The data to encrypt.
     * @return The encrypted data.
     * @throws GeneralSecurityException A Crypto Error Occurred.
     */
    byte[] encrypt(byte[] data) throws GeneralSecurityException;

    /**
     * Encrypts data using {@link #getKey()} symmetric key to the same passed data buffer.
     *
     * @param data The data buffer to use.
     * @throws GeneralSecurityException A Crypto Error Occurred.
     */
    void encryptInPlace(byte[] data) throws GeneralSecurityException;

    /**
     * Encrypts a stream using {@link #getKey()} symmetric key.
     *
     * @param in The {@link InputStream} to encrypt.
     * @param out The {@link OutputStream}.
     * @throws IOException  A Stream I/O Issue occurred.
     * @throws GeneralSecurityException A Crypto Error Occurred.
     */
    void encryptStream(InputStream in, OutputStream out) throws IOException, GeneralSecurityException;

    /**
     * Decrypts from a stream using {@link #getKey()} symmetric key.
     *
     * @param in The {@link InputStream}.
     * @param len The number of bytes to read.
     * @return The decrypted data.
     * @throws IOException  A Stream I/O Issue occurred.
     * @throws GeneralSecurityException A Crypto Error Occurred.
     */
    byte[] decryptFromStream(InputStream in, int len) throws IOException, GeneralSecurityException;

    /**
     * Decrypts data using {@link #getKey()} symmetric key.
     *
     * @param data The data to decrypt.
     * @return The decrypted data.
     * @throws GeneralSecurityException A Crypto Error Occurred.
     */
    byte[] decrypt(byte[] data) throws GeneralSecurityException;

    /**
     * Decrypts data using {@link #getKey()} symmetric key to the same passed data buffer.
     *
     * @param data The data buffer to use.
     * @throws GeneralSecurityException A Crypto Error Occurred.
     */
    void decryptInPlace(byte[] data) throws GeneralSecurityException;

    /**
     * Decrypts a stream using {@link #getKey()} symmetric key.
     *
     * @param in The {@link InputStream}.
     * @param out The decrypted {@link OutputStream}.
     * @throws IOException  A Stream I/O Issue occurred.
     * @throws GeneralSecurityException A Crypto Error Occurred.
     */
    void decryptStream(InputStream in, OutputStream out) throws IOException, GeneralSecurityException;
}
