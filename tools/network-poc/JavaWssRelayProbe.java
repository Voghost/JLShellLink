import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/** One-shot A/C WSS byte relay. Diagnostic only; not a product service. */
public final class JavaWssRelayProbe {
    private static final String GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static final byte[] PLAINTEXT = "JLSHELL-P0-SECRET-PAYLOAD".getBytes(StandardCharsets.US_ASCII);
    private static final int MAX_FRAME = 65_536;
    private final String token;
    private final String session;
    private final CountDownLatch stopped = new CountDownLatch(1);
    private final ByteArrayOutputStream captured = new ByteArrayOutputStream();
    private Connection a;
    private Connection c;
    private long aToC;
    private long cToA;
    private int aFrames;
    private int cFrames;

    private JavaWssRelayProbe(String token, String session) {
        this.token = token;
        this.session = session;
    }

    private static SSLContext context(Path identity, char[] password) throws Exception {
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(identity)) {
            keys.load(input, password);
        }
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keys, password);
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(factory.getKeyManagers(), null, null);
        return context;
    }

    private static String line(InputStream input) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int previous = -1;
        int value;
        while ((value = input.read()) >= 0) {
            bytes.write(value);
            if (previous == '\r' && value == '\n') {
                byte[] raw = bytes.toByteArray();
                return new String(raw, 0, raw.length - 2, StandardCharsets.US_ASCII);
            }
            if (bytes.size() > 8_192) {
                throw new IOException("WSS header line is too large");
            }
            previous = value;
        }
        throw new IOException("WSS handshake ended early");
    }

    private static Map<String, String> headers(InputStream input) throws IOException {
        if (!line(input).equals("GET /link/v2/relay HTTP/1.1")) {
            throw new IOException("Unexpected WSS request path");
        }
        Map<String, String> headers = new HashMap<>();
        for (int i = 0; i < 32; i++) {
            String current = line(input);
            if (current.isEmpty()) {
                return headers;
            }
            int colon = current.indexOf(':');
            if (colon <= 0) {
                throw new IOException("Invalid WSS header");
            }
            headers.put(current.substring(0, colon).trim().toLowerCase(),
                    current.substring(colon + 1).trim());
        }
        throw new IOException("Too many WSS headers");
    }

    private static int nextByte(InputStream input) throws IOException {
        int value = input.read();
        if (value < 0) {
            throw new IOException("WSS connection closed");
        }
        return value;
    }

    private record Frame(int opcode, byte[] payload) {}

    private static Frame readFrame(InputStream input) throws IOException {
        int first = nextByte(input);
        int second = nextByte(input);
        boolean fin = (first & 0x80) != 0;
        int opcode = first & 15;
        boolean masked = (second & 0x80) != 0;
        long length = second & 127;
        if (length == 126) {
            length = (nextByte(input) << 8) | nextByte(input);
        } else if (length == 127) {
            length = 0;
            for (int i = 0; i < 8; i++) {
                length = (length << 8) | nextByte(input);
            }
        }
        if (!fin || !masked || length > MAX_FRAME || (opcode >= 8 && length > 125)) {
            throw new IOException("Unsupported or oversized WSS frame");
        }
        byte[] mask = input.readNBytes(4);
        byte[] payload = input.readNBytes((int) length);
        if (mask.length != 4 || payload.length != length) {
            throw new IOException("Truncated WSS frame");
        }
        for (int i = 0; i < payload.length; i++) {
            payload[i] ^= mask[i & 3];
        }
        return new Frame(opcode, payload);
    }

    private static void writeFrame(OutputStream output, int opcode, byte[] payload) throws IOException {
        if (payload.length > MAX_FRAME) {
            throw new IOException("WSS frame too large");
        }
        output.write(0x80 | opcode);
        if (payload.length < 126) {
            output.write(payload.length);
        } else {
            output.write(126);
            output.write(payload.length >>> 8);
            output.write(payload.length);
        }
        output.write(payload);
        output.flush();
    }

    private synchronized boolean attach(Connection connection) {
        if (connection.role.equals("A") && a == null) {
            a = connection;
        } else if (connection.role.equals("C") && c == null) {
            c = connection;
        } else {
            return false;
        }
        notifyAll();
        if (a != null && c != null) {
            System.out.println("WSS_PAIR_READY");
        }
        return true;
    }

    private synchronized void awaitPair() throws InterruptedException, IOException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        while ((a == null || c == null) && System.nanoTime() < deadline) {
            wait(200);
        }
        if (a == null || c == null) {
            throw new IOException("WSS peer did not arrive");
        }
    }

    private synchronized void forward(Connection source, byte[] payload) throws IOException {
        Connection target = source == a ? c : a;
        if (target == null) {
            throw new IOException("WSS pair is incomplete");
        }
        captured.writeBytes(payload);
        if (source == a) {
            aToC += payload.length;
            aFrames++;
        } else {
            cToA += payload.length;
            cFrames++;
        }
        synchronized (target.output) {
            writeFrame(target.output, 2, payload);
        }
    }

    private void serve(SSLSocket socket) {
        try (socket) {
            socket.setEnabledProtocols(new String[] {"TLSv1.3"});
            socket.setSoTimeout(30_000);
            socket.startHandshake();
            InputStream input = socket.getInputStream();
            OutputStream output = socket.getOutputStream();
            Map<String, String> request = headers(input);
            byte[] expected = ("Bearer " + token).getBytes(StandardCharsets.US_ASCII);
            byte[] actual = request.getOrDefault("authorization", "").getBytes(StandardCharsets.US_ASCII);
            String role = request.get("x-link-role");
            String key = request.get("sec-websocket-key");
            if (!MessageDigest.isEqual(expected, actual)
                    || !session.equals(request.get("x-link-session"))
                    || !("A".equals(role) || "C".equals(role))
                    || !"websocket".equalsIgnoreCase(request.get("upgrade"))
                    || !"13".equals(request.get("sec-websocket-version"))
                    || key == null || Base64.getDecoder().decode(key).length != 16) {
                output.write("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
                        .getBytes(StandardCharsets.US_ASCII));
                output.flush();
                return;
            }
            byte[] hash = MessageDigest.getInstance("SHA-1")
                    .digest((key + GUID).getBytes(StandardCharsets.US_ASCII));
            String accept = Base64.getEncoder().encodeToString(hash);
            output.write(("HTTP/1.1 101 Switching Protocols\r\n"
                    + "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                    + "Sec-WebSocket-Accept: " + accept + "\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            output.flush();
            Connection connection = new Connection(role, socket, output);
            if (!attach(connection)) {
                return;
            }
            awaitPair();
            while (true) {
                Frame frame = readFrame(input);
                if (frame.opcode == 8) {
                    synchronized (output) {
                        writeFrame(output, 8, frame.payload);
                    }
                    return;
                }
                if (frame.opcode == 9) {
                    synchronized (output) {
                        writeFrame(output, 10, frame.payload);
                    }
                } else if (frame.opcode == 2) {
                    forward(connection, frame.payload);
                } else {
                    throw new IOException("Unexpected WSS opcode");
                }
            }
        } catch (Exception error) {
            System.out.println("WSS_PEER_END " + error.getClass().getSimpleName());
        } finally {
            stopped.countDown();
        }
    }

    private record Connection(String role, Socket socket, OutputStream output) {}

    private void run(SSLContext tls, int port, long seconds) throws Exception {
        try (SSLServerSocket listener = (SSLServerSocket) tls.getServerSocketFactory()
                .createServerSocket()) {
            listener.setEnabledProtocols(new String[] {"TLSv1.3"});
            listener.bind(new InetSocketAddress("0.0.0.0", port));
            listener.setSoTimeout(500);
            System.out.println("LISTEN wss/" + port);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
            int accepted = 0;
            while (accepted < 2 && System.nanoTime() < deadline) {
                try {
                    SSLSocket peer = (SSLSocket) listener.accept();
                    Thread.ofVirtual().start(() -> serve(peer));
                    accepted++;
                } catch (SocketTimeoutException ignored) {
                    // Bounded wait for A and C.
                }
            }
            if (accepted != 2) {
                throw new IOException("WSS clients did not both connect");
            }
            stopped.await(25, TimeUnit.SECONDS);
            synchronized (this) {
                if (a != null) {
                    a.socket.close();
                }
                if (c != null) {
                    c.socket.close();
                }
                System.out.println("FORWARDED_A_C " + aToC + " frames=" + aFrames);
                System.out.println("FORWARDED_C_A " + cToA + " frames=" + cFrames);
                System.out.println("PLAINTEXT_SEEN " + contains(captured.toByteArray(), PLAINTEXT));
            }
        }
    }

    private static boolean contains(byte[] data, byte[] needle) {
        outer:
        for (int i = 0; i <= data.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 6) {
            throw new IllegalArgumentException(
                    "Usage: JavaWssRelayProbe <port> <identity.p12> <storepass> <token> <session> <seconds>");
        }
        SSLContext tls = context(Path.of(args[1]), args[2].toCharArray());
        new JavaWssRelayProbe(args[3], args[4]).run(tls, Integer.parseInt(args[0]),
                Long.parseLong(args[5]));
    }
}
