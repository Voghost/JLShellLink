package com.jlshell.link.core.model;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.Objects;

public record CidrBlock(String network, int prefixLength) {
    public CidrBlock {
        network = TargetEndpoint.normalizeLiteral(network);
        byte[] bytes = bytes(network);
        int bits = bytes.length * 8;
        if (prefixLength < 0 || prefixLength > bits) {
            throw new IllegalArgumentException("CIDR prefix is outside address width");
        }
        network = InetAddressString.of(mask(bytes, prefixLength));
    }

    public static CidrBlock parse(String cidr) {
        Objects.requireNonNull(cidr, "cidr");
        int slash = cidr.lastIndexOf('/');
        if (slash <= 0 || slash == cidr.length() - 1) {
            throw new IllegalArgumentException("CIDR must contain address/prefix");
        }
        return new CidrBlock(cidr.substring(0, slash), Integer.parseInt(cidr.substring(slash + 1)));
    }

    public static CidrBlock exact(String address) {
        String normalized = TargetEndpoint.normalizeLiteral(address);
        return new CidrBlock(normalized, bytes(normalized).length * 8);
    }

    public boolean contains(String address) {
        byte[] candidate = bytes(TargetEndpoint.normalizeLiteral(address));
        byte[] base = bytes(network);
        return candidate.length == base.length && Arrays.equals(mask(candidate, prefixLength), base);
    }

    private static byte[] bytes(String address) {
        return new TargetEndpoint(address, 1).inetAddress().getAddress();
    }

    private static byte[] mask(byte[] address, int prefix) {
        byte[] result = address.clone();
        int fullBytes = prefix / 8;
        int remainingBits = prefix % 8;
        if (remainingBits != 0) {
            result[fullBytes] &= (byte) (0xff << (8 - remainingBits));
            fullBytes++;
        }
        Arrays.fill(result, fullBytes, result.length, (byte) 0);
        return result;
    }

    @Override
    public String toString() {
        return network + "/" + prefixLength;
    }

    private static final class InetAddressString {
        private static String of(byte[] address) {
            try {
                return InetAddress.getByAddress(address).getHostAddress();
            } catch (java.net.UnknownHostException impossible) {
                throw new IllegalStateException(impossible);
            }
        }
    }
}
