import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.net.ssl.SSLSocket;

/** A deliberately narrow HTTP/2 CONNECT wire probe, not a general HTTP/2 stack. */
public final class JavaHttp2ConnectProbe {
    private static final byte[] PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            .getBytes(StandardCharsets.US_ASCII);
    private static final int TARGET_PORT = 13779;
    private static final int DATA = 0;
    private static final int HEADERS = 1;
    private static final int SETTINGS = 4;
    private static final int END_STREAM = 1;
    private static final int END_HEADERS = 4;
    private static final int ACK = 1;
    private static final int MAX_FRAME = 16_384;

    private record Frame(int type, int flags, int stream, byte[] payload) {}

    private static void send(OutputStream out, int type, int flags, int stream, byte[] payload)
            throws IOException {
        if (payload.length > MAX_FRAME || stream < 0) {
            throw new IOException("Invalid HTTP/2 probe frame");
        }
        out.write(payload.length >>> 16);
        out.write(payload.length >>> 8);
        out.write(payload.length);
        out.write(type);
        out.write(flags);
        out.write(stream >>> 24);
        out.write(stream >>> 16);
        out.write(stream >>> 8);
        out.write(stream);
        out.write(payload);
        out.flush();
    }

    private static Frame read(InputStream in) throws IOException {
        byte[] header = in.readNBytes(9);
        if (header.length != 9) {
            throw new IOException("Short HTTP/2 frame header");
        }
        int length = (header[0] & 255) << 16 | (header[1] & 255) << 8 | header[2] & 255;
        int stream = (header[5] & 127) << 24 | (header[6] & 255) << 16
                | (header[7] & 255) << 8 | header[8] & 255;
        if (length > MAX_FRAME) {
            throw new IOException("Oversized HTTP/2 probe frame");
        }
        byte[] payload = in.readNBytes(length);
        if (payload.length != length) {
            throw new IOException("Short HTTP/2 frame payload");
        }
        return new Frame(header[3] & 255, header[4] & 255, stream, payload);
    }

    private static void require(Frame frame, int type, int flags, int stream) throws IOException {
        if (frame.type != type || frame.flags != flags || frame.stream != stream) {
            throw new IOException("Unexpected HTTP/2 frame: " + frame);
        }
    }

    private static byte[] requestHeaders() {
        byte[] authority = ("127.0.0.1:" + TARGET_PORT).getBytes(StandardCharsets.US_ASCII);
        byte[] headers = new byte[2 + 7 + 2 + authority.length];
        int i = 0;
        headers[i++] = 0x02; // HPACK literal without indexing, static name :method.
        headers[i++] = 7;
        for (byte value : "CONNECT".getBytes(StandardCharsets.US_ASCII)) headers[i++] = value;
        headers[i++] = 0x01; // HPACK literal without indexing, static name :authority.
        headers[i++] = (byte) authority.length;
        for (byte value : authority) headers[i++] = value;
        return headers;
    }

    private static byte[] payload() {
        byte[] message = new byte[4096];
        byte[] marker = "JLSHELL-P0-SECRET-PAYLOAD".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(marker, 0, message, 0, marker.length);
        for (int i = marker.length; i < message.length; i++) message[i] = (byte) (i * 31 + 7);
        return message;
    }

    public static void client(SSLSocket tls) throws Exception {
        InputStream in = tls.getInputStream();
        OutputStream out = tls.getOutputStream();
        out.write(PREFACE);
        send(out, SETTINGS, 0, 0, new byte[0]);
        send(out, HEADERS, END_HEADERS, 1, requestHeaders());
        require(read(in), SETTINGS, 0, 0);
        send(out, SETTINGS, ACK, 0, new byte[0]);
        require(read(in), SETTINGS, ACK, 0);
        Frame response = read(in);
        require(response, HEADERS, END_HEADERS, 1);
        if (!Arrays.equals(response.payload, new byte[] {(byte) 0x88})) {
            throw new IOException("CONNECT did not return HTTP/2 :status 200");
        }
        byte[] message = payload();
        send(out, DATA, END_STREAM, 1, message);
        Frame echoed = read(in);
        require(echoed, DATA, END_STREAM, 1);
        if (!Arrays.equals(message, echoed.payload)) {
            throw new IOException("HTTP/2 CONNECT target echo mismatch");
        }
        System.out.println("HTTP2_CONNECT_ECHO_VERIFIED bytes=" + message.length
                + " target=127.0.0.1:" + TARGET_PORT + " half_close=true");
    }

    public static void server(SSLSocket tls) throws Exception {
        try (ServerSocket targetListener = new ServerSocket(TARGET_PORT, 1,
                InetAddress.getLoopbackAddress())) {
            Thread target = Thread.ofVirtual().start(() -> {
                try (Socket socket = targetListener.accept()) {
                    socket.getInputStream().transferTo(socket.getOutputStream());
                    socket.shutdownOutput();
                } catch (IOException failure) {
                    throw new RuntimeException(failure);
                }
            });
            InputStream in = tls.getInputStream();
            OutputStream out = tls.getOutputStream();
            if (!Arrays.equals(PREFACE, in.readNBytes(PREFACE.length))) {
                throw new IOException("Invalid HTTP/2 client preface");
            }
            require(read(in), SETTINGS, 0, 0);
            Frame headers = read(in);
            require(headers, HEADERS, END_HEADERS, 1);
            if (!Arrays.equals(requestHeaders(), headers.payload)) {
                throw new IOException("Unexpected CONNECT authority or HPACK fields");
            }
            try (Socket targetSocket = new Socket(InetAddress.getLoopbackAddress(), TARGET_PORT)) {
                targetSocket.setSoTimeout(10_000);
                send(out, SETTINGS, 0, 0, new byte[0]);
                send(out, SETTINGS, ACK, 0, new byte[0]);
                send(out, HEADERS, END_HEADERS, 1, new byte[] {(byte) 0x88}); // :status 200.
                require(read(in), SETTINGS, ACK, 0);
                Frame data = read(in);
                require(data, DATA, END_STREAM, 1);
                targetSocket.getOutputStream().write(data.payload);
                targetSocket.shutdownOutput();
                byte[] echoed = targetSocket.getInputStream().readNBytes(data.payload.length);
                if (echoed.length != data.payload.length
                        || targetSocket.getInputStream().read() != -1) {
                    throw new IOException("TCP target did not echo and half-close");
                }
                send(out, DATA, END_STREAM, 1, echoed);
                target.join(3_000);
                System.out.println("HTTP2_CONNECT_TARGET_C bytes=" + echoed.length
                        + " half_close=true");
            }
        }
    }
}
