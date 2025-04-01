package com.captainalm.lib.mesh.packets.data;

import java.io.ByteArrayInputStream;

/**
 * Provides a cryptographic nonce accessor interface.
 *
 * @author Alfred Manville
 */
public interface INonce {
    /**
     * Gets the nonce in stream form.
     *
     * @return The nonce stream.
     */
    ByteArrayInputStream getNonceStream();
}
