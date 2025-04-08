package com.captainalm.lib.mesh.handshake;

/**
 * Provides an interface for peer authorizers.
 *
 * @author Alfred Manville
 */
public interface IPeerAuthorizer {
    /**
     * Authorizes a peer
     * @param ID The ID of the peer.
     * @param recommendationPubKey The recommendation public DSA key, if verified.
     * @return If the peer should be authorized.
     */
    boolean authorize(byte[] ID, byte[] recommendationPubKey);
}
