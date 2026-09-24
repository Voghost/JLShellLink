import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;

/** B-signalled UDP punch diagnostic using external STUN; not ICE or KCP. */
public final class JavaUdpPathProbe {
    private static final int MAGIC = 0x2112A442;

    private static InetSocketAddress mapping(DatagramSocket socket, String host, int port) throws Exception {
        byte[] transaction = new byte[12];
        new SecureRandom().nextBytes(transaction);
        ByteBuffer request = ByteBuffer.allocate(20);
        request.putShort((short) 0x0001).putShort((short) 0).putInt(MAGIC).put(transaction);
        InetAddress server = InetAddress.getByName(host);
        byte[] response = new byte[1500];
        socket.setSoTimeout(2000);
        for (int attempt = 0; attempt < 3; attempt++) {
            socket.send(new DatagramPacket(request.array(), 20, server, port));
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
                byte[] returned = new byte[12];
                bytes.get(returned);
                if (!Arrays.equals(transaction, returned)) {
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
                        if (Byte.toUnsignedInt(bytes.get()) != 1) {
                            break;
                        }
                        int mappedPort = Short.toUnsignedInt(bytes.getShort()) ^ (MAGIC >>> 16);
                        byte[] address = new byte[4];
                        bytes.get(address);
                        byte[] mask = ByteBuffer.allocate(4).putInt(MAGIC).array();
                        for (int i = 0; i < 4; i++) {
                            address[i] ^= mask[i];
                        }
                        return new InetSocketAddress(InetAddress.getByAddress(address), mappedPort);
                    }
                    bytes.position(Math.min(next, bytes.limit()));
                }
            } catch (SocketTimeoutException ignored) {
                // Retry a bounded binding request.
            }
        }
        throw new IllegalStateException("STUN did not return an IPv4 binding mapping");
    }

    private static void send(DatagramSocket socket, String data, InetSocketAddress address) throws Exception {
        byte[] payload = data.getBytes(StandardCharsets.US_ASCII);
        socket.send(new DatagramPacket(payload, payload.length, address));
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 6 || !(args[0].equals("A") || args[0].equals("C"))) {
            throw new IllegalArgumentException(
                    "Usage: JavaUdpPathProbe <A|C> <stun-host> <B-host> <B-port> <token> <seconds>");
        }
        String role = args[0];
        String otherRole = role.equals("A") ? "C" : "A";
        String token = args[4];
        try (DatagramSocket udp = new DatagramSocket();
                Socket signal = new Socket(args[2], Integer.parseInt(args[3]))) {
            signal.setSoTimeout(30_000);
            InetSocketAddress mapped = mapping(udp, args[1], 3478);
            System.out.println("LOCAL_PORT " + role + " " + udp.getLocalPort());
            System.out.println("STUN_MAPPING " + role + " " + mapped.getAddress().getHostAddress()
                    + ":" + mapped.getPort());
            signal.getOutputStream().write(("JLSHELL-P0 " + role + " " + token + "\n"
                    + "MAPPED " + mapped.getAddress().getHostAddress() + " " + mapped.getPort() + "\n")
                    .getBytes(StandardCharsets.US_ASCII));
            signal.getOutputStream().flush();
            String candidate = new BufferedReader(new InputStreamReader(signal.getInputStream(),
                    StandardCharsets.US_ASCII)).readLine();
            if (candidate == null) {
                throw new IllegalStateException("B closed before peer candidate exchange");
            }
            String[] fields = candidate.split(" ");
            if (fields.length != 3 || !fields[0].equals("MAPPED")) {
                throw new IllegalStateException("Unexpected peer candidate");
            }
            InetSocketAddress peer = new InetSocketAddress(InetAddress.getByName(fields[1]),
                    Integer.parseInt(fields[2]));
            System.out.println("B_CANDIDATE " + role + " " + peer.getAddress().getHostAddress()
                    + ":" + peer.getPort());
            udp.setSoTimeout(200);
            long deadline = System.nanoTime() + Duration.ofSeconds(Long.parseLong(args[5])).toNanos();
            byte[] incoming = new byte[1500];
            boolean direct = false;
            while (System.nanoTime() < deadline) {
                send(udp, "PUNCH " + role + " " + token, peer);
                try {
                    DatagramPacket packet = new DatagramPacket(incoming, incoming.length);
                    udp.receive(packet);
                    String message = new String(packet.getData(), 0, packet.getLength(),
                            StandardCharsets.US_ASCII);
                    if (message.equals("PUNCH " + otherRole + " " + token)) {
                        direct = true;
                        peer = new InetSocketAddress(packet.getAddress(), packet.getPort());
                        send(udp, "ACK " + role + " " + token, peer);
                    } else if (message.equals("ACK " + otherRole + " " + token)) {
                        for (int i = 0; i < 3; i++) {
                            send(udp, "ACK " + role + " " + token, peer);
                        }
                        System.out.println("DIRECT_BIDIRECTIONAL " + role);
                        return;
                    }
                } catch (SocketTimeoutException ignored) {
                    // Keep punching until the bounded deadline.
                }
            }
            System.out.println("DIRECT_RESULT " + role + " " + (direct ? "one-way" : "unreachable"));
        }
    }
}
