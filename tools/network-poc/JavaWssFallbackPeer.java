import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/** Real-network direct timeout then WSS + inner mTLS diagnostic. */
public final class JavaWssFallbackPeer {
    private static final int DIRECT_BUDGET_MS = 2_000;

    private static SSLContext context(Path identity, Path trust, char[] password) throws Exception {
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        if (identity != null) {
            KeyStore store = KeyStore.getInstance("PKCS12");
            try (InputStream input = Files.newInputStream(identity)) {
                store.load(input, password);
            }
            keys.init(store, password);
        }
        KeyStore trusted = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(trust)) {
            trusted.load(input, password);
        }
        TrustManagerFactory trusts = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trusts.init(trusted);
        SSLContext tls = SSLContext.getInstance("TLSv1.3");
        tls.init(identity == null ? null : keys.getKeyManagers(), trusts.getTrustManagers(), null);
        return tls;
    }

    private static InetSocketAddress candidate(DatagramSocket udp, String role,
            String host, int stunPort, int signalPort, String token) throws Exception {
        String stunHost = System.getProperty("jlshell.p0.stunHost", host);
        InetSocketAddress mapped = JavaUdpPathProbe.mapping(udp, stunHost, stunPort);
        String override = System.getProperty("jlshell.p0.advertise");
        if (override != null) {
            String[] parts = override.split(":", 2);
            if (parts.length != 2) throw new IllegalArgumentException("Invalid advertised candidate");
            mapped = new InetSocketAddress(InetAddress.getByName(parts[0]), Integer.parseInt(parts[1]));
        }
        System.out.println("CANDIDATE " + role + " " + mapped);
        try (Socket signal = new Socket(host, signalPort)) {
            signal.setSoTimeout(90_000);
            signal.getOutputStream().write(("JLSHELL-P0 " + role + " " + token + "\n"
                    + "MAPPED " + mapped.getAddress().getHostAddress() + " " + mapped.getPort() + "\n")
                    .getBytes(StandardCharsets.US_ASCII));
            signal.getOutputStream().flush();
            ByteArrayOutputStream line = new ByteArrayOutputStream();
            int next;
            while ((next = signal.getInputStream().read()) >= 0 && next != '\n' && line.size() < 100) {
                line.write(next);
            }
            if (next != '\n') {
                throw new IOException("B did not return a peer candidate");
            }
            String[] fields = line.toString(StandardCharsets.US_ASCII).split(" ");
            if (fields.length != 3 || !fields[0].equals("MAPPED")) {
                throw new IOException("Invalid B candidate response");
            }
            return new InetSocketAddress(InetAddress.getByName(fields[1]), Integer.parseInt(fields[2]));
        }
    }

    private static boolean directAttempt(DatagramSocket udp, InetSocketAddress peer, String token,
            boolean expectSuccess, boolean allowOsDeny)
            throws Exception {
        udp.setSoTimeout(100);
        byte[] message = ("PUNCH A " + token).getBytes(StandardCharsets.US_ASCII);
        byte[] received = new byte[1500];
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(DIRECT_BUDGET_MS);
        int sent = 0;
        int denied = 0;
        while (System.nanoTime() < deadline) {
            try {
                udp.send(new DatagramPacket(message, message.length, peer));
                sent++;
            } catch (SocketException failure) {
                if (!allowOsDeny || !"Operation not permitted".equals(failure.getMessage())) {
                    throw failure;
                }
                denied++;
            }
            try {
                DatagramPacket packet = new DatagramPacket(received, received.length);
                udp.receive(packet);
                String answer = new String(packet.getData(), 0, packet.getLength(), StandardCharsets.US_ASCII);
                if (answer.equals("ACK C " + token)) {
                    if (!expectSuccess) {
                        throw new IllegalStateException("Direct path unexpectedly succeeded during drop test");
                    }
                    System.out.println("DIRECT_BASELINE_VERIFIED packets=" + sent);
                    return true;
                }
            } catch (java.net.SocketTimeoutException ignored) {
                // Deliberately bounded direct attempt.
            }
        }
        if (expectSuccess) throw new IOException("Direct baseline did not succeed");
        System.out.println("DIRECT_TIMEOUT budget_ms=" + DIRECT_BUDGET_MS + " packets=" + sent
                + " os_denied=" + denied);
        return false;
    }

    private static Thread receiveDirect(DatagramSocket udp, InetSocketAddress peer, String token,
            AtomicInteger receivedCount, boolean reply) {
        return Thread.ofVirtual().start(() -> {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            byte[] bytes = new byte[1500];
            try {
                udp.setSoTimeout(100);
                while (System.nanoTime() < deadline) {
                    try {
                        if (reply) {
                            byte[] punch = ("PUNCH C " + token).getBytes(StandardCharsets.US_ASCII);
                            udp.send(new DatagramPacket(punch, punch.length, peer));
                        }
                        DatagramPacket packet = new DatagramPacket(bytes, bytes.length);
                        udp.receive(packet);
                        if (new String(packet.getData(), 0, packet.getLength(), StandardCharsets.US_ASCII)
                                .equals("PUNCH A " + token)) {
                            receivedCount.incrementAndGet();
                            if (reply) {
                                byte[] ack = ("ACK C " + token).getBytes(StandardCharsets.US_ASCII);
                                udp.send(new DatagramPacket(ack, ack.length, packet.getSocketAddress()));
                            }
                        }
                    } catch (java.net.SocketTimeoutException ignored) {
                        // Keep the same socket and mapping open during the direct budget.
                    }
                }
            } catch (IOException error) {
                throw new RuntimeException(error);
            }
        });
    }

    private static final class BinaryListener implements WebSocket.Listener {
        private final ArrayBlockingQueue<byte[]> messages = new ArrayBlockingQueue<>(32);
        private final ByteArrayOutputStream parts = new ByteArrayOutputStream();
        private volatile WebSocket socket;
        private volatile Throwable error;
        private volatile boolean ended;

        @Override
        public void onOpen(WebSocket webSocket) {
            socket = webSocket;
            webSocket.request(1);
        }

        @Override
        public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer bytes, boolean last) {
            byte[] part = new byte[bytes.remaining()];
            bytes.get(part);
            parts.writeBytes(part);
            if (parts.size() > 65_536) {
                error = new IOException("WSS message exceeded test limit");
                webSocket.abort();
                return CompletableFuture.completedFuture(null);
            }
            if (last) {
                if (!messages.offer(parts.toByteArray())) {
                    error = new IOException("WSS receive queue is full");
                    webSocket.abort();
                    return CompletableFuture.completedFuture(null);
                }
                parts.reset();
            }
            if (messages.remainingCapacity() > 0) {
                webSocket.request(1);
            }
            return CompletableFuture.completedFuture(null);
        }

        private byte[] next() throws IOException {
            try {
                byte[] message = messages.poll(10, TimeUnit.SECONDS);
                if (message == null) {
                    if (error != null) {
                        throw new IOException("WSS receive failed", error);
                    }
                    if (ended) {
                        return null;
                    }
                    throw new IOException("WSS receive timed out");
                }
                if (messages.remainingCapacity() > 0 && socket != null) {
                    socket.request(1);
                }
                return message;
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted WSS receive", error);
            }
        }

        @Override
        public void onError(WebSocket webSocket, Throwable failure) {
            error = failure;
            ended = true;
        }

        @Override
        public CompletionStage<?> onClose(WebSocket webSocket, int code, String reason) {
            ended = true;
            return CompletableFuture.completedFuture(null);
        }
    }

    /** Provides blocking stream semantics for an inner JSSE session. */
    private static final class WssStreamSocket extends Socket {
        private final WebSocket webSocket;
        private final BinaryListener listener;
        private volatile boolean closed;
        private final InputStream input = new InputStream() {
            private byte[] current = new byte[0];
            private int offset;

            @Override
            public int read() throws IOException {
                byte[] value = new byte[1];
                return read(value, 0, 1) < 0 ? -1 : value[0] & 0xff;
            }

            @Override
            public int read(byte[] target, int start, int length) throws IOException {
                if (length == 0) {
                    return 0;
                }
                while (offset == current.length) {
                    byte[] message = listener.next();
                    if (message == null) {
                        return -1;
                    }
                    current = message;
                    offset = 0;
                }
                int count = Math.min(length, current.length - offset);
                System.arraycopy(current, offset, target, start, count);
                offset += count;
                return count;
            }
        };
        private final OutputStream output = new OutputStream() {
            @Override
            public void write(int value) throws IOException {
                write(new byte[] {(byte) value}, 0, 1);
            }

            @Override
            public void write(byte[] bytes, int start, int length) throws IOException {
                if (closed) {
                    throw new SocketException("WSS stream is closed");
                }
                if (length == 0) {
                    return;
                }
                try {
                    webSocket.sendBinary(ByteBuffer.wrap(Arrays.copyOfRange(bytes, start, start + length)), true)
                            .get(5, TimeUnit.SECONDS);
                } catch (Exception error) {
                    throw new IOException("WSS send failed", error);
                }
            }
        };

        private WssStreamSocket(WebSocket webSocket, BinaryListener listener) {
            this.webSocket = webSocket;
            this.listener = listener;
        }

        @Override public InputStream getInputStream() { return input; }
        @Override public OutputStream getOutputStream() { return output; }
        @Override public InetAddress getInetAddress() { return InetAddress.getLoopbackAddress(); }
        @Override public int getPort() { return 443; }
        @Override public SocketAddress getRemoteSocketAddress() {
            return new InetSocketAddress(getInetAddress(), getPort());
        }
        @Override public boolean isConnected() { return true; }
        @Override public boolean isBound() { return true; }
        @Override public boolean isClosed() { return closed; }
        @Override public void close() {
            closed = true;
            webSocket.abort();
        }
    }

    public static void main(String[] args) throws Exception {
        if ((args.length != 9 && args.length != 11)
                || !(args[0].equals("A") || args[0].equals("C"))) {
            throw new IllegalArgumentException("Usage: JavaWssFallbackPeer <A|C> <B-host> <stun-port>"
                    + " <signal-port> <wss-port> <workdir> <token> <session> <storepass>"
                    + " [<echo|http2> <app-drop|os-block|os-baseline>]");
        }
        String role = args[0];
        String host = args[1];
        Path directory = Path.of(args[5]);
        String token = args[6];
        char[] password = args[8].toCharArray();
        String protocol = args.length == 11 ? args[9] : "echo";
        String dropMode = args.length == 11 ? args[10] : "app-drop";
        if (!(protocol.equals("echo") || protocol.equals("http2"))
                || !(dropMode.equals("app-drop") || dropMode.equals("os-block")
                        || dropMode.equals("os-baseline"))) {
            throw new IllegalArgumentException("Unknown protocol or drop mode");
        }
        try (DatagramSocket udp = new DatagramSocket(
                Integer.getInteger("jlshell.p0.udpPort", 0))) {
            InetSocketAddress peer = candidate(udp, role, host, Integer.parseInt(args[2]),
                    Integer.parseInt(args[3]), token);
            AtomicInteger dropped = new AtomicInteger();
            Thread dropper = null;
            if (role.equals("A")) {
                directAttempt(udp, peer, token, dropMode.equals("os-baseline"),
                        dropMode.equals("os-block"));
                if (dropMode.equals("os-baseline")) return;
                System.out.println("RELAY_ATTEMPTS 1");
            } else {
                dropper = receiveDirect(udp, peer, token, dropped, !dropMode.equals("app-drop"));
                if (dropMode.equals("os-baseline")) {
                    dropper.join(6_000);
                    System.out.println("DIRECT_BASELINE_RECEIVED " + dropped.get());
                    if (dropped.get() == 0) throw new IOException("C received no baseline UDP");
                    return;
                }
            }
            SSLContext outer = context(null, directory.resolve("B-trust.p12"), password);
            HttpClient client = HttpClient.newBuilder().sslContext(outer)
                    .connectTimeout(Duration.ofSeconds(5)).build();
            BinaryListener listener = new BinaryListener();
            URI endpoint = URI.create("wss://" + host + ":" + args[4] + "/link/v2/relay");
            WebSocket webSocket = client.newWebSocketBuilder()
                    .header("Authorization", "Bearer " + token)
                    .header("X-Link-Session", args[7])
                    .header("X-Link-Role", role)
                    .buildAsync(endpoint, listener).get(10, TimeUnit.SECONDS);
            System.out.println("WSS_CONNECTED " + role);
            SSLContext inner = context(directory.resolve(role + ".p12"),
                    directory.resolve(role + "-trust.p12"), password);
            try (WssStreamSocket transport = new WssStreamSocket(webSocket, listener);
                    SSLSocket secure = (SSLSocket) inner.getSocketFactory()
                            .createSocket(transport, "inner-c", 443, true)) {
                secure.setUseClientMode(role.equals("A"));
                secure.setEnabledProtocols(new String[] {"TLSv1.3"});
                if (role.equals("A")) {
                    var parameters = secure.getSSLParameters();
                    parameters.setEndpointIdentificationAlgorithm("HTTPS");
                    if (protocol.equals("http2")) parameters.setApplicationProtocols(new String[] {"h2"});
                    secure.setSSLParameters(parameters);
                } else {
                    secure.setNeedClientAuth(true);
                    if (protocol.equals("http2")) {
                        var parameters = secure.getSSLParameters();
                        parameters.setApplicationProtocols(new String[] {"h2"});
                        secure.setSSLParameters(parameters);
                    }
                }
                secure.startHandshake();
                System.out.println("INNER_TLS " + role + " " + secure.getSession().getProtocol());
                if (protocol.equals("http2")) {
                    if (!secure.getApplicationProtocol().equals("h2")) {
                        throw new IOException("Inner TLS did not negotiate h2 ALPN");
                    }
                    System.out.println("INNER_ALPN h2");
                    if (role.equals("A")) JavaHttp2ConnectProbe.client(secure);
                    else JavaHttp2ConnectProbe.server(secure);
                } else if (role.equals("A")) {
                    DataInputStream input = new DataInputStream(secure.getInputStream());
                    DataOutputStream output = new DataOutputStream(secure.getOutputStream());
                    byte[] message = new byte[4096];
                    byte[] marker = "JLSHELL-P0-SECRET-PAYLOAD".getBytes(StandardCharsets.US_ASCII);
                    System.arraycopy(marker, 0, message, 0, marker.length);
                    for (int i = marker.length; i < message.length; i++) {
                        message[i] = (byte) (i * 31 + 7);
                    }
                    output.writeInt(message.length);
                    output.write(message);
                    output.flush();
                    int length = input.readInt();
                    if (length != message.length || !Arrays.equals(message, input.readNBytes(length))) {
                        throw new IOException("WSS fallback echo mismatch");
                    }
                    System.out.println("WSS_ECHO_VERIFIED bytes=" + length);
                } else {
                    DataInputStream input = new DataInputStream(secure.getInputStream());
                    DataOutputStream output = new DataOutputStream(secure.getOutputStream());
                    int length = input.readInt();
                    if (length != 4096) {
                        throw new IOException("Unexpected WSS echo size");
                    }
                    byte[] message = input.readNBytes(length);
                    if (message.length != length) {
                        throw new IOException("Short WSS echo request");
                    }
                    output.writeInt(length);
                    output.write(message);
                    output.flush();
                    System.out.println("WSS_ECHO_C bytes=" + length);
                    Thread.sleep(250);
                }
            }
            if (dropper != null) {
                dropper.join(6_000);
                System.out.println((dropMode.equals("app-drop") ? "DIRECT_DROPPED " : "DIRECT_RECEIVED ")
                        + dropped.get());
                if (dropMode.equals("app-drop") && dropped.get() == 0) {
                    throw new IllegalStateException("C did not observe direct UDP packets to drop");
                }
            }
        }
    }
}
