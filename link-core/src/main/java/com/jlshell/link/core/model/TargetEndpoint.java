package com.jlshell.link.core.model;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Objects;

/** Numeric TCP target. Hostnames are rejected to prevent policy checks from racing DNS. */
public record TargetEndpoint(String address, int port) {
    public TargetEndpoint {
        address = normalizeLiteral(address);
        if (port < 1 || port > 65_535) {
            throw new IllegalArgumentException("Port must be between 1 and 65535");
        }
    }

    public InetAddress inetAddress() {
        try {
            return InetAddress.getByName(address);
        } catch (UnknownHostException impossible) {
            throw new IllegalStateException("Previously validated numeric address became invalid", impossible);
        }
    }

    public InetSocketAddress socketAddress() {
        return new InetSocketAddress(inetAddress(), port);
    }

    static String normalizeLiteral(String value) {
        Objects.requireNonNull(value, "address");
        if (value.isBlank() || value.indexOf('%') >= 0) {
            throw new IllegalArgumentException("Address must be an unscoped numeric IP literal");
        }
        try {
            if (value.indexOf(':') >= 0) {
                return InetAddress.getByName(value).getHostAddress();
            }
            String[] octets = value.split("\\.", -1);
            if (octets.length != 4) throw new IllegalArgumentException("Address must be numeric");
            byte[] bytes = new byte[4];
            for (int index = 0; index < octets.length; index++) {
                if (octets[index].isEmpty() || (octets[index].length() > 1 && octets[index].startsWith("0"))) {
                    throw new IllegalArgumentException("IPv4 octets must use canonical decimal form");
                }
                int octet = Integer.parseInt(octets[index]);
                if (octet < 0 || octet > 255) throw new IllegalArgumentException("IPv4 octet out of range");
                bytes[index] = (byte) octet;
            }
            return InetAddress.getByAddress(bytes).getHostAddress();
        } catch (UnknownHostException | NumberFormatException error) {
            throw new IllegalArgumentException("Address must be a numeric IP literal", error);
        }
    }
}
