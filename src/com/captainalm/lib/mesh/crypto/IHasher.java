package com.captainalm.lib.mesh.crypto;

import java.io.IOException;
import java.io.InputStream;

/**
 * Provides a data hasher.
 *
 * @author Alfred Manville
 */
public interface IHasher {
    /**
     * Hashes the passed data.
     *
     * @param data The data to hash.
     * @return The hash of the data.
     */
    byte[] hash(byte[] data);

    /**
     * Hashes the passed {@link InputStream} consuming the contents specified by len.
     *
     * @param inputStream The stream to read from.
     * @param len The number of bytes to read from the stream.
     * @return The hash of the data.
     * @throws IOException A Stream I/O Issue occurred.
     */
    byte[] hashStream(InputStream inputStream, int len) throws IOException;
}
