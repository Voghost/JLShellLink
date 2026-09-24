import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Arrays;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/** One-shot mTLS echo probe for two outbound peers through JavaTcpRelay. */
public final class JavaTlsPeer {
    private static SSLContext context(Path directory, String role, char[] password) throws Exception {
        KeyStore identity = KeyStore.getInstance("PKCS12");
        try (var stream = java.nio.file.Files.newInputStream(directory.resolve(role + ".p12"))) {
            identity.load(stream, password);
        }
        KeyStore trust = KeyStore.getInstance("PKCS12");
        try (var stream = java.nio.file.Files.newInputStream(directory.resolve(role + "-trust.p12"))) {
            trust.load(stream, password);
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(identity, password);
        TrustManagerFactory trusted = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trusted.init(trust);
        SSLContext tls = SSLContext.getInstance("TLSv1.3");
        tls.init(keys.getKeyManagers(), trusted.getTrustManagers(), null);
        return tls;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 6 || !(args[0].equals("A") || args[0].equals("C"))) {
            throw new IllegalArgumentException("Usage: JavaTlsPeer <A|C> <host> <port> <directory> <token> <storepass>");
        }
        String role = args[0];
        SSLContext tls = context(Path.of(args[3]), role, args[5].toCharArray());
        try (Socket tcp = new Socket(args[1], Integer.parseInt(args[2]))) {
            tcp.setSoTimeout(30_000);
            tcp.getOutputStream().write(("JLSHELL-P0 " + role + " " + args[4] + "\n")
                    .getBytes(StandardCharsets.US_ASCII));
            tcp.getOutputStream().flush();
            try (SSLSocket secure = (SSLSocket) tls.getSocketFactory().createSocket(tcp, args[1],
                    Integer.parseInt(args[2]), true)) {
                secure.setEnabledProtocols(new String[] {"TLSv1.3"});
                secure.setUseClientMode(role.equals("A"));
                if (role.equals("C")) {
                    secure.setNeedClientAuth(true);
                }
                secure.startHandshake();
                System.out.println("TLS " + role + " " + secure.getSession().getProtocol());
                DataInputStream input = new DataInputStream(secure.getInputStream());
                DataOutputStream output = new DataOutputStream(secure.getOutputStream());
                if (role.equals("A")) {
                    byte[] message = new byte[4096];
                    byte[] marker = "JLSHELL-P0-SECRET-PAYLOAD".getBytes(StandardCharsets.US_ASCII);
                    System.arraycopy(marker, 0, message, 0, marker.length);
                    for (int i = marker.length; i < message.length; i++) {
                        message[i] = (byte) (i * 31 + 7);
                    }
                    output.writeInt(message.length);
                    output.write(message);
                    output.flush();
                    int size = input.readInt();
                    if (size != message.length) {
                        throw new IllegalStateException("Unexpected echo size: " + size);
                    }
                    byte[] echoed = input.readNBytes(size);
                    if (!Arrays.equals(message, echoed)) {
                        throw new IllegalStateException("Echo payload corrupted");
                    }
                    System.out.println("ECHO A verified bytes=" + size);
                } else {
                    int size = input.readInt();
                    if (size != 4096) {
                        throw new IllegalStateException("Unexpected incoming size: " + size);
                    }
                    byte[] message = input.readNBytes(size);
                    if (message.length != size) {
                        throw new IllegalStateException("Short incoming message");
                    }
                    output.writeInt(size);
                    output.write(message);
                    output.flush();
                    System.out.println("ECHO C bytes=" + size);
                }
            }
        }
    }
}
