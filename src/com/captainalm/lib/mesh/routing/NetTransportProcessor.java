package com.captainalm.lib.mesh.routing;

import com.captainalm.lib.mesh.packets.Packet;
import com.captainalm.lib.mesh.packets.PacketType;
import com.captainalm.lib.mesh.packets.UnicastPacket;
import com.captainalm.lib.mesh.packets.data.DataAddressedPayload;
import com.captainalm.lib.mesh.packets.data.DataPayload;
import com.captainalm.lib.mesh.packets.data.PacketData;
import com.captainalm.lib.mesh.transport.INetTransport;
import com.captainalm.lib.mesh.utils.BytesToHex;
import com.captainalm.lib.mesh.utils.IP;

/**
 * Provides a {@link IPacketProcessor} to interface with {@link INetTransport}.
 *
 * @author Alfred Manville
 */
public final class NetTransportProcessor implements IPacketProcessor {
    private Router router;
    private final INetTransport transport;

    private final Thread recvThread = new Thread(new Runnable() {
        public void run() {
            while (transport.isActive()) {
                byte[] data = transport.receive();
                if (data == null)
                    return;
                byte[] dest = IP.extractDestinationAddress(data);
                byte[] srcID = router.getThisNodeID();
                boolean remote = false;
                if (IP.getVersion(data[0]) == 4) {
                    remote = dest[0] != 10;
                } else if (IP.getVersion(data[0]) == 6) {
                    remote = dest[0] != (byte) 253 || dest[1] != (byte) 10;
                }
                byte[] dstID = (remote ? router.getGatewayNodeID() : router.getNodeID(BytesToHex.bytesToHex(dest)));
                if (dstID != null) {
                    PacketData payload = (remote ? new DataAddressedPayload(data, false) : new DataPayload(data));
                    router.send((UnicastPacket) new UnicastPacket(payload.getSize()).setDestinationAddress(dstID).setSourceAddress(srcID)
                            .setPacketType((remote) ? PacketType.UnicastDataAddressed : PacketType.UnicastData)
                            .setPacketData(payload).timeStamp());
                }
            }
        }
    });

    /**
     * Constructs a new Instance of NetTransportProcessor with the specified {@link INetTransport}.
     *
     * @param transport The network transport.
     */
    public NetTransportProcessor(INetTransport transport) {
        if (transport == null)
            throw new NullPointerException("transport cannot be null");
        this.transport = transport;
    }

    /**
     * Receives a packet.
     *
     * @param packet The received packet.
     */
    @Override
    public void processPacket(Packet packet) {
        if (!transport.isActive())
            return;
        if (packet instanceof UnicastPacket upk && (packet.getType() == PacketType.UnicastData || packet.getType() == PacketType.UnicastDataAddressed)) {
            if (packet.getPacketData(true) instanceof DataPayload payload)
                transport.send(payload.getIpPacket(upk.getSourceAddress(), upk.getDestinationAddress()));
        }
    }

    /**
     * Send the router instance.
     *
     * @param router Gives the router instance to the processor.
     */
    @Override
    public void obtainRouter(Router router) {
        if (router == null)
            throw new NullPointerException("router cannot be null");
        this.router = router;
        recvThread.start();
    }

    /**
     * Terminates the processor.
     */
    @Override
    public void terminate() {
       if(transport.isActive())
           transport.close();
    }
}
