package com.jlshell.link.stun;

import com.jlshell.link.server.StunBindingServer;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.util.concurrent.CountDownLatch;

/** Runs the same Binding-only responder as the embedded Website listener on a public host. */
public final class PublicStunApplication {
    private PublicStunApplication() {}

    public static void main(String[] args) throws InterruptedException {
        String bindAddress = System.getenv().getOrDefault("JLSHELL_LINK_STUN_BIND_ADDRESS", "0.0.0.0");
        int port = Integer.parseInt(System.getenv().getOrDefault("JLSHELL_LINK_STUN_PORT", "13576"));
        int requestsPerSecond = Integer.parseInt(
                System.getenv().getOrDefault("JLSHELL_LINK_STUN_MAX_REQUESTS_PER_SECOND", "100"));
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("STUN port must be between 1 and 65535");
        }
        StunBindingServer server = new StunBindingServer(
                new InetSocketAddress(bindAddress, port), Clock.systemUTC(), requestsPerSecond);
        Runtime.getRuntime().addShutdownHook(new Thread(server::close, "link-stun-shutdown"));
        InetSocketAddress listener = server.start().toCompletableFuture().join();
        System.out.println("JLShell Link STUN Binding listener ready on UDP " + listener.getPort());
        new CountDownLatch(1).await();
    }
}
