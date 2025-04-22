package test;

import com.captainalm.lib.mesh.crypto.IHasher;
import com.captainalm.lib.mesh.packets.Packet;
import com.captainalm.lib.mesh.packets.PacketBytesInputStream;
import com.captainalm.lib.mesh.packets.PacketType;
import com.captainalm.lib.mesh.packets.data.SinglePayload;
import com.captainalm.lib.mesh.utils.LengthClampedInputStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * Provides some tests.
 *
 * @author Alfred Manville
 */
public class Tests {
    public static void main(String[] args) {
        IHasher hasher = new Hasher();
        SinglePayload sp = new SinglePayload(new byte[] {1,3,3,7});
        println(sp.getPayload());
        Packet packet = new Packet(sp.getSize()).setPacketType(PacketType.DirectHandshakeAccept).setPacketData(sp).setTTL((byte) 4).timeStamp();
        println(packet.timeStampInRange());
        println(packet.getPacketBytes());
        byte[] toread = new byte[packet.getPacketBytes().length * 2];
        System.arraycopy(packet.getPacketBytes(), 0, toread, 0, packet.getPacketBytes().length);
        System.arraycopy(packet.getPacketBytes(),0 , toread, packet.getPacketBytes().length, packet.getPacketBytes().length);
        sp = (SinglePayload) (Packet.getPacketFromBytes(packet.getPacketBytes())).getPacketData(true);
        println(sp.getPayload());
        PacketBytesInputStream ins = new PacketBytesInputStream(new LengthClampedInputStream(new ByteArrayInputStream(toread), toread.length));
        byte[] buff = null;
        try {
            while ((buff = ins.readNext()) != null) {
                println(buff);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void println(byte[] bytes) {
        if (bytes != null) {
            System.out.print(bytes.length);
            System.out.print(" - [");
            for (byte b : bytes)
                System.out.printf("%02x", b);
            System.out.println("]");
            return;
        }
        System.out.println("<null>");
    }

    private static void println(boolean b) {
        System.out.println(b);
    }

    private static void println(int i) {
        System.out.println(i);
    }

    private static void println(String s) {
        System.out.println(s);
    }
}
