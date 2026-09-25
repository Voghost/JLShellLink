import com.jlshell.link.transport.poc.IceComponentDatagramAdapter;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import kcp.IKcp;
import kcp.Kcp;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.Agent;
import org.ice4j.ice.CandidatePair;
import org.ice4j.ice.CandidateType;
import org.ice4j.ice.Component;
import org.ice4j.ice.IceMediaStream;
import org.ice4j.ice.KeepAliveStrategy;
import org.ice4j.ice.LocalCandidate;
import org.ice4j.ice.RemoteCandidate;
import org.ice4j.ice.harvest.StunCandidateHarvester;

/** Single-session cross-NAT ICE/KCP/mTLS/HTTP2 diagnostic, never a product endpoint. */
public final class JavaIceKcpHttp2Peer {
    private record CandidateInfo(CandidateType type, String host, int port,
                                 String foundation, long priority) {
        private String wire() {
            return type.name() + "," + host + "," + port + "," + foundation + "," + priority;
        }

        private static CandidateInfo parse(String wire) {
            String[] fields = wire.split(",", -1);
            if (fields.length != 5) throw new IllegalArgumentException("Invalid candidate fields");
            return new CandidateInfo(CandidateType.valueOf(fields[0]), fields[1],
                    Integer.parseInt(fields[2]), fields[3], Long.parseLong(fields[4]));
        }

        private String address() { return host + ":" + port; }
    }

    private record PeerInfo(String ufrag, String password, List<CandidateInfo> candidates) {
        private String wire() {
            StringBuilder result = new StringBuilder("ICE1 ").append(ufrag).append(' ')
                    .append(password);
            for (CandidateInfo candidate : candidates) result.append(' ').append(candidate.wire());
            return result.toString();
        }

        private static PeerInfo parse(String line) {
            String[] fields = line.split(" ");
            if (fields.length < 4 || !fields[0].equals("ICE1")) {
                throw new IllegalArgumentException("Invalid peer ICE announcement");
            }
            List<CandidateInfo> candidates = new ArrayList<>();
            for (int i = 3; i < fields.length; i++) candidates.add(CandidateInfo.parse(fields[i]));
            return new PeerInfo(fields[1], fields[2], candidates);
        }
    }

    private static SSLContext tls(Path directory, String role, char[] password) throws Exception {
        KeyStore identity = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(directory.resolve(role + ".p12"))) {
            identity.load(input, password);
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(identity, password);
        KeyStore trusted = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(directory.resolve(role + "-trust.p12"))) {
            trusted.load(input, password);
        }
        TrustManagerFactory trusts = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trusts.init(trusted);
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keys.getKeyManagers(), trusts.getTrustManagers(), null);
        return context;
    }

    private static void quietLibraryLogs() {
        java.util.logging.Logger root = java.util.logging.Logger.getLogger("");
        root.setLevel(java.util.logging.Level.SEVERE);
        for (java.util.logging.Handler handler : root.getHandlers()) {
            handler.setLevel(java.util.logging.Level.SEVERE);
        }
    }

    private static List<CandidateInfo> localCandidates(Component component, String role) {
        List<CandidateInfo> result = new ArrayList<>();
        for (LocalCandidate candidate : component.getLocalCandidates()) {
            CandidateType type = candidate.getType();
            if (type != CandidateType.HOST_CANDIDATE
                    && type != CandidateType.SERVER_REFLEXIVE_CANDIDATE) continue;
            TransportAddress address = candidate.getTransportAddress();
            if (!(address.getAddress() instanceof Inet4Address)
                    || address.getAddress().isLoopbackAddress()) continue;
            CandidateInfo info = new CandidateInfo(type, address.getHostAddress(),
                    address.getPort(), candidate.getFoundation(), candidate.getPriority());
            result.add(info);
            System.out.println("POC_CANDIDATE " + role + " " + type + " " + info.address());
        }
        if (result.stream().noneMatch(c -> c.type == CandidateType.SERVER_REFLEXIVE_CANDIDATE)) {
            throw new IllegalStateException("B STUN yielded no server-reflexive candidate");
        }
        return result;
    }

    private static void addRemote(Component component, PeerInfo peer) {
        for (CandidateInfo candidate : peer.candidates) {
            component.addRemoteCandidate(new RemoteCandidate(
                    new TransportAddress(candidate.host, candidate.port, Transport.UDP),
                    component, candidate.type, candidate.foundation, candidate.priority, null));
        }
    }

    private static final class KcpByteSocket extends Socket {
        private final IceComponentDatagramAdapter adapter;
        private final Kcp engine;
        private final ArrayBlockingQueue<byte[]> received = new ArrayBlockingQueue<>(4);
        private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform().name("p0-cross-nat-kcp-timer-", 0).factory());
        private final AtomicBoolean closed = new AtomicBoolean();
        private final AtomicReference<IOException> receiverError = new AtomicReference<>();
        private final Thread receiver;
        private final InputStream input = new InputStream() {
            private byte[] current = new byte[0];
            private int offset;

            @Override public int read() throws IOException {
                byte[] one = new byte[1];
                return read(one, 0, 1) < 0 ? -1 : one[0] & 255;
            }

            @Override public int read(byte[] bytes, int start, int length) throws IOException {
                if (length == 0) return 0;
                while (offset == current.length) {
                    if (closed.get()) return -1;
                    IOException error = receiverError.get();
                    if (error != null) throw error;
                    try {
                        current = received.poll(20, TimeUnit.SECONDS);
                    } catch (InterruptedException errorInterrupted) {
                        Thread.currentThread().interrupt();
                        throw new IOException("KCP read interrupted", errorInterrupted);
                    }
                    if (current == null) throw new SocketTimeoutException("KCP application read timed out");
                    offset = 0;
                    synchronized (engine) { drain(); }
                }
                int count = Math.min(length, current.length - offset);
                System.arraycopy(current, offset, bytes, start, count);
                offset += count;
                return count;
            }
        };
        private final OutputStream output = new OutputStream() {
            @Override public void write(int value) throws IOException {
                write(new byte[] {(byte) value}, 0, 1);
            }

            @Override public void write(byte[] bytes, int start, int length) throws IOException {
                if (closed.get()) throw new SocketException("KCP socket closed");
                if (length == 0) return;
                byte[] copy = java.util.Arrays.copyOfRange(bytes, start, start + length);
                synchronized (engine) {
                    ByteBuf data = Unpooled.wrappedBuffer(copy);
                    try {
                        int result = engine.send(data);
                        if (result < 0) throw new IOException("KCP rejected TLS data: " + result);
                        engine.update(System.currentTimeMillis());
                    } finally { data.release(); }
                }
            }
        };

        private KcpByteSocket(Component component, SocketAddress remote) throws SocketException {
            component.getSocket().setSoTimeout(100);
            adapter = new IceComponentDatagramAdapter(component.getSocket(), remote, this::receiveSegment);
            engine = new Kcp(0x4A4C5348, this::sendSegment);
            engine.nodelay(true, 10, 2, true);
            engine.setSndWnd(64);
            engine.setRcvWnd(64);
            engine.setMtu(1_200);
            engine.setStream(true);
            receiver = Thread.ofVirtual().start(() -> {
                while (!closed.get()) {
                    try { adapter.receiveOne(1_200); }
                    catch (SocketTimeoutException ignored) { }
                    catch (IOException error) {
                        if (!closed.get()) receiverError.compareAndSet(null, error);
                        return;
                    }
                }
            });
            timer.scheduleAtFixedRate(() -> {
                synchronized (engine) {
                    if (!closed.get()) engine.update(System.currentTimeMillis());
                }
            }, 0, 10, TimeUnit.MILLISECONDS);
        }

        private void sendSegment(ByteBuf segment, IKcp ignored) {
            try {
                byte[] packet = new byte[segment.readableBytes()];
                segment.getBytes(segment.readerIndex(), packet);
                adapter.send(packet);
            } catch (IOException error) {
                receiverError.compareAndSet(null, error);
                throw new IllegalStateException("KCP datagram send failed", error);
            } finally { segment.release(); }
        }

        private void receiveSegment(byte[] packet) {
            synchronized (engine) {
                engine.input(Unpooled.wrappedBuffer(packet), true, System.currentTimeMillis());
                drain();
                if (engine.checkFlush()) engine.flush(false, System.currentTimeMillis());
            }
        }

        private void drain() {
            while (received.remainingCapacity() > 0) {
                List<ByteBuf> messages = new ArrayList<>(1);
                if (engine.recv(messages) <= 0) return;
                for (ByteBuf message : messages) {
                    try {
                        byte[] bytes = new byte[message.readableBytes()];
                        message.readBytes(bytes);
                        if (!received.offer(bytes)) throw new IllegalStateException("KCP queue exceeded four chunks");
                    } finally { message.release(); }
                }
            }
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
        @Override public boolean isClosed() { return closed.get(); }
        @Override public void close() throws IOException {
            if (!closed.compareAndSet(false, true)) return;
            timer.shutdownNow();
            try { receiver.join(1_000); }
            catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while stopping KCP", error);
            }
            if (receiver.isAlive()) throw new IOException("KCP receiver did not stop");
            synchronized (engine) { engine.release(); }
        }
    }

    public static void main(String[] args) throws Exception {
        if (!((args.length == 9 && (args[8].equals("ice") || args[8].equals("full")))
                || (args.length == 11 && args[8].equals("auto")))
                || !(args[0].equals("A") || args[0].equals("C"))) {
            throw new IllegalArgumentException("Usage: JavaIceKcpHttp2Peer <A|C> <interface> <B-host>"
                    + " <B-stun-port> <B-signal-port> <workdir> <token> <storepass>"
                    + " <ice|full|auto> [<B-wss-port> <session>]");
        }
        quietLibraryLogs();
        String role = args[0];
        InetAddress bIpv4 = java.util.Arrays.stream(InetAddress.getAllByName(args[2]))
                .filter(address -> address instanceof Inet4Address)
                .findFirst().orElseThrow(() -> new IOException("B has no IPv4 address"));
        System.setProperty("ice4j.harvest.mapping.aws.enabled", "false");
        System.setProperty("org.ice4j.ice.harvest.ALLOWED_INTERFACES", args[1]);
        System.setProperty("ice4j.harvest.use-ipv6", "false");
        System.setProperty("ice4j.harvest.use-link-local-addresses", "false");
        Agent agent = new Agent();
        agent.setControlling(role.equals("A"));
        boolean relayFallback = false;
        try {
            agent.addCandidateHarvester(new StunCandidateHarvester(
                    new TransportAddress(bIpv4, Integer.parseInt(args[3]), Transport.UDP)));
            IceMediaStream stream = agent.createMediaStream("link");
            Component component = agent.createComponent(stream, 0, 0, 0,
                    KeepAliveStrategy.SELECTED_ONLY, true);
            List<CandidateInfo> candidates = localCandidates(component, role);
            PeerInfo local = new PeerInfo(agent.getLocalUfrag(), agent.getLocalPassword(), candidates);
            try (Socket signal = new Socket(bIpv4, Integer.parseInt(args[4]))) {
                signal.setSoTimeout(90_000);
                signal.getOutputStream().write(("JLSHELL-P0 " + role + " " + args[6] + "\n"
                        + local.wire() + "\n").getBytes(StandardCharsets.US_ASCII));
                signal.getOutputStream().flush();
                BufferedReader lines = new BufferedReader(new InputStreamReader(
                        signal.getInputStream(), StandardCharsets.US_ASCII));
                PeerInfo peer = PeerInfo.parse(lines.readLine());
                stream.setRemoteUfrag(peer.ufrag);
                stream.setRemotePassword(peer.password);
                addRemote(component, peer);
                long started = System.nanoTime();
                agent.startConnectivityEstablishment();
                long budgetMs = args[8].equals("auto") ? 2_000 : 30_000;
                long deadline = started + TimeUnit.MILLISECONDS.toNanos(budgetMs);
                CandidatePair selected;
                while ((selected = component.getSelectedPair()) == null
                        && System.nanoTime() < deadline) Thread.sleep(20);
                boolean localDirect = selected != null && selected.isNominated();
                if (!args[8].equals("auto") && !localDirect) {
                    throw new IOException("ICE did not nominate a pair; state=" + agent.getState());
                }
                long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
                if (localDirect) {
                    System.out.println("POC_ICE_SELECTED " + role + " local="
                            + selected.getLocalCandidate().getType() + ":"
                            + selected.getLocalCandidate().getTransportAddress().getHostAddress() + ":"
                            + selected.getLocalCandidate().getTransportAddress().getPort() + " remote="
                            + selected.getRemoteCandidate().getType() + ":"
                            + selected.getRemoteCandidate().getTransportAddress().getHostAddress() + ":"
                            + selected.getRemoteCandidate().getTransportAddress().getPort()
                            + " elapsed_ms=" + elapsedMs);
                }
                signal.getOutputStream().write(("PATH " + (localDirect ? "DIRECT" : "RELAY")
                        + "\n").getBytes(StandardCharsets.US_ASCII));
                signal.getOutputStream().flush();
                String peerPath = lines.readLine();
                if (!("PATH DIRECT".equals(peerPath) || "PATH RELAY".equals(peerPath))) {
                    throw new IOException("Peer did not announce its ICE path");
                }
                if (args[8].equals("auto") && (!localDirect || peerPath.equals("PATH RELAY"))) {
                    relayFallback = true;
                    System.out.println("POC_ICE_FALLBACK " + role + " budget_ms=" + budgetMs
                            + " local=" + (localDirect ? "DIRECT" : "RELAY")
                            + " peer=" + peerPath.substring(5));
                } else if (!localDirect || !peerPath.equals("PATH DIRECT")) {
                    throw new IOException("ICE path mismatch");
                }
                if (!relayFallback) {
                    if (args[8].equals("ice")) return;
                    try (KcpByteSocket transport = new KcpByteSocket(component,
                            selected.getRemoteCandidate().getTransportAddress());
                            SSLSocket secure = (SSLSocket) tls(Path.of(args[5]), role, args[7].toCharArray())
                                    .getSocketFactory().createSocket(transport, "inner-c", 443, true)) {
                        secure.setUseClientMode(role.equals("A"));
                        secure.setEnabledProtocols(new String[] {"TLSv1.3"});
                        var parameters = secure.getSSLParameters();
                        parameters.setApplicationProtocols(new String[] {"h2"});
                        if (role.equals("A")) parameters.setEndpointIdentificationAlgorithm("HTTPS");
                        else parameters.setNeedClientAuth(true);
                        secure.setSSLParameters(parameters);
                        secure.startHandshake();
                        if (!"h2".equals(secure.getApplicationProtocol())) {
                            throw new IOException("ICE/KCP inner TLS did not negotiate h2");
                        }
                        System.out.println("POC_DIRECT_TLS " + role + " "
                                + secure.getSession().getProtocol() + " ALPN=h2");
                        if (role.equals("A")) JavaHttp2ConnectProbe.client(secure);
                        else JavaHttp2ConnectProbe.server(secure);
                    }
                }
            }
        } finally {
            agent.free();
            System.out.println("POC_RESOURCES_RELEASED " + role + " agent_over=" + agent.isOver());
        }
        if (relayFallback) {
            JavaWssFallbackPeer.main(new String[] {role, args[2], "0", "0", args[9], args[5],
                    args[6], args[10], args[7], "http2", "relay-only"});
        }
    }
}
