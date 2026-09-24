import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

/** Minimal RFC 5389 IPv4 binding diagnostic; not an ICE or product STUN client. */
public final class JavaStunProbe {
    private static final int MAGIC = 0x2112A442;

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException("Usage: JavaStunProbe <stun-host> <port>");
        }
        byte[] transaction = new byte[12];
        new SecureRandom().nextBytes(transaction);
        ByteBuffer request = ByteBuffer.allocate(20);
        request.putShort((short) 0x0001).putShort((short) 0).putInt(MAGIC).put(transaction);
        InetAddress server = InetAddress.getByName(args[0]);
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(2_000);
            byte[] response = new byte[1500];
            for (int attempt = 1; attempt <= 3; attempt++) {
                socket.send(new DatagramPacket(request.array(), 20, server, Integer.parseInt(args[1])));
                try {
                    DatagramPacket packet = new DatagramPacket(response, response.length);
                    socket.receive(packet);
                    ByteBuffer bytes = ByteBuffer.wrap(packet.getData(), 0, packet.getLength());
                    if (bytes.remaining() < 20 || Short.toUnsignedInt(bytes.getShort()) != 0x0101) {
                        continue;
                    }
                    int payloadLength = Short.toUnsignedInt(bytes.getShort());
                    if (bytes.getInt() != MAGIC || payloadLength > packet.getLength() - 20) {
                        continue;
                    }
                    byte[] receivedTransaction = new byte[12];
                    bytes.get(receivedTransaction);
                    if (!Arrays.equals(transaction, receivedTransaction)) {
                        continue;
                    }
                    while (bytes.remaining() >= 4) {
                        int type = Short.toUnsignedInt(bytes.getShort());
                        int length = Short.toUnsignedInt(bytes.getShort());
                        if (length > bytes.remaining()) {
                            break;
                        }
                        int next = bytes.position() + ((length + 3) & ~3);
                        if (type == 0x0020 && length >= 8) {
                            bytes.get();
                            int family = Byte.toUnsignedInt(bytes.get());
                            if (family != 1) {
                                break;
                            }
                            int mappedPort = Short.toUnsignedInt(bytes.getShort()) ^ (MAGIC >>> 16);
                            byte[] address = new byte[4];
                            bytes.get(address);
                            ByteBuffer mask = ByteBuffer.allocate(4).putInt(MAGIC);
                            for (int i = 0; i < 4; i++) {
                                address[i] ^= mask.array()[i];
                            }
                            System.out.println("LOCAL_PORT " + socket.getLocalPort());
                            System.out.println("MAPPED " + InetAddress.getByAddress(address).getHostAddress()
                                    + ":" + mappedPort);
                            return;
                        }
                        bytes.position(Math.min(next, bytes.limit()));
                    }
                } catch (java.net.SocketTimeoutException ignored) {
                    // Retry only this bounded probe.
                }
            }
        }
        throw new IllegalStateException("No valid IPv4 STUN binding response after three attempts");
    }
}
