package com.captainalm.lib.mesh.utils;

import java.io.IOException;
import java.io.InputStream;

/**
 * This provides the ability to skip bytes without counting towards the read limitt of {@link LengthClampedInputStream}.
 *
 * @author Alfred Manville
 */
public class SkippedLengthClampedInputStream extends LengthClampedInputStream {
    /**
     * Creates a SkippedLengthClampedInputStream with the specified {@link InputStream}
     * and the maximum number of bytes that can be read from the stream and the number of bytes to skip.
     * This skip does not count towards the read length limit.
     *
     * @param inputStream   The input stream to clamp.
     * @param length        The maximum number of bytes that can be read before end of stream is reached.
     * @param skippedLength The number of bytes to skip.
     * @throws NullPointerException     inputStream is null.
     * @throws IllegalArgumentException length is less than 0.
     */
    public SkippedLengthClampedInputStream(InputStream inputStream, int length, int skippedLength) throws IOException {
        super(inputStream, length);
        inputStream.skip(length);
    }
}
