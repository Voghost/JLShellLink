import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;

/** Bounded IPv4 STUN Binding diagnostic on B. Not a production STUN service. */
public final class JavaStunServer {
    private static final int MAGIC = 0x2112A442;

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException("Usage: JavaStunServer <port> <max-seconds>");
        }
        int port = Integer.parseInt(args[0]);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(Long.parseLong(args[1]));
        int answered = 0;
        try (DatagramSocket socket = new DatagramSocket(port)) {
            socket.setSoTimeout(500);
            System.out.println("LISTEN udp/" + port);
            byte[] incoming = new byte[1500];
            while (System.nanoTime() < deadline) {
                DatagramPacket request = new DatagramPacket(incoming, incoming.length);
                try {
                    socket.receive(request);
                } catch (SocketTimeoutException ignored) {
                    continue;
                }
                if (!(request.getAddress() instanceof Inet4Address) || request.getLength() < 20) {
                    continue;
                }
                ByteBuffer bytes = ByteBuffer.wrap(request.getData(), 0, request.getLength());
                if (Short.toUnsignedInt(bytes.getShort()) != 0x0001) {
                    continue;
                }
                int attributesLength = Short.toUnsignedInt(bytes.getShort());
                if (bytes.getInt() != MAGIC || attributesLength > request.getLength() - 20) {
                    continue;
                }
                byte[] transaction = new byte[12];
                bytes.get(transaction);
                byte[] address = request.getAddress().getAddress();
                byte[] mask = ByteBuffer.allocate(4).putInt(MAGIC).array();
                ByteBuffer response = ByteBuffer.allocate(32);
                response.putShort((short) 0x0101).putShort((short) 12).putInt(MAGIC)
                        .put(transaction)
                        .putShort((short) 0x0020).putShort((short) 8)
                        .put((byte) 0).put((byte) 1)
                        .putShort((short) (request.getPort() ^ (MAGIC >>> 16)));
                for (int i = 0; i < 4; i++) {
                    response.put((byte) (address[i] ^ mask[i]));
                }
                socket.send(new DatagramPacket(response.array(), response.position(),
                        request.getAddress(), request.getPort()));
                answered++;
                System.out.println("BINDING_RESPONSE " + answered);
            }
        }
        System.out.println("TOTAL_BINDING_RESPONSES " + answered);
    }
}
