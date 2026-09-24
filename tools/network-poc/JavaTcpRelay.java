import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/** One-shot diagnostic byte relay. It is not a production Link service. */
public final class JavaTcpRelay {
    private static final byte[] MARKER = "JLSHELL-P0-SECRET-PAYLOAD".getBytes(StandardCharsets.US_ASCII);

    private static String header(Socket socket) throws IOException {
        byte[] bytes = new byte[128];
        int count = 0;
        while (count < bytes.length) {
            int next = socket.getInputStream().read();
            if (next < 0) {
                throw new IOException("Connection ended before role header");
            }
            if (next == '\n') {
                return new String(bytes, 0, count, StandardCharsets.US_ASCII);
            }
            bytes[count++] = (byte) next;
        }
        throw new IOException("Role header too long");
    }

    private static boolean contains(byte[] haystack, int length, byte[] needle) {
        for (int i = 0; i <= length - needle.length; i++) {
            int j = 0;
            while (j < needle.length && haystack[i + j] == needle[j]) {
                j++;
            }
            if (j == needle.length) {
                return true;
            }
        }
        return false;
    }

    private static Thread pump(Socket source, Socket destination, String label,
            AtomicLong count, AtomicBoolean plaintextSeen) {
        Thread worker = Thread.ofPlatform().name("p0-relay-" + label).start(() -> {
            byte[] buffer = new byte[16384];
            try {
                int length;
                while ((length = source.getInputStream().read(buffer)) >= 0) {
                    count.addAndGet(length);
                    if (contains(buffer, length, MARKER)) {
                        plaintextSeen.set(true);
                    }
                    destination.getOutputStream().write(buffer, 0, length);
                    destination.getOutputStream().flush();
                }
            } catch (IOException ignored) {
                // Both sockets are closed by the owning thread after the bounded test.
            } finally {
                try {
                    destination.shutdownOutput();
                } catch (IOException ignored) {
                    // The peer already closed its connection.
                }
            }
        });
        return worker;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            throw new IllegalArgumentException("Usage: JavaTcpRelay <port> <token> <seconds>");
        }
        int port = Integer.parseInt(args[0]);
        String token = args[1];
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(Long.parseLong(args[2]));
        Socket a = null;
        Socket c = null;
        try (ServerSocket listener = new ServerSocket(port)) {
            listener.setSoTimeout(500);
            System.out.println("LISTEN tcp/" + port);
            while (System.nanoTime() < deadline && (a == null || c == null)) {
                try {
                    Socket candidate = listener.accept();
                    candidate.setSoTimeout(30_000);
                    String role;
                    try {
                        role = header(candidate);
                    } catch (IOException error) {
                        candidate.close();
                        continue;
                    }
                    if (role.equals("JLSHELL-P0 A " + token) && a == null) {
                        a = candidate;
                        System.out.println("PAIRED_ROLE A");
                    } else if (role.equals("JLSHELL-P0 C " + token) && c == null) {
                        c = candidate;
                        System.out.println("PAIRED_ROLE C");
                    } else {
                        candidate.close();
                    }
                } catch (SocketTimeoutException ignored) {
                    // Recheck the bounded test deadline.
                }
            }
            if (a == null || c == null) {
                throw new IOException("A/C did not pair within test deadline");
            }
            AtomicLong aToC = new AtomicLong();
            AtomicLong cToA = new AtomicLong();
            AtomicBoolean plaintextSeen = new AtomicBoolean();
            Thread forward = pump(a, c, "A-C", aToC, plaintextSeen);
            Thread reverse = pump(c, a, "C-A", cToA, plaintextSeen);
            forward.join(20_000);
            reverse.join(20_000);
            System.out.println("FORWARDED A-C " + aToC.get());
            System.out.println("FORWARDED C-A " + cToA.get());
            System.out.println("PLAINTEXT_SEEN " + plaintextSeen.get());
            if (forward.isAlive() || reverse.isAlive()) {
                throw new IOException("Relay workers exceeded test deadline");
            }
        } finally {
            if (a != null) {
                a.close();
            }
            if (c != null) {
                c.close();
            }
        }
    }
}
