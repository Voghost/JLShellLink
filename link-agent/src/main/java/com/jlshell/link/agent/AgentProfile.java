package com.jlshell.link.agent;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import com.jlshell.link.core.model.TargetEndpoint;

/** Public connection parameters only; tokens and identity passwords never enter this file. */
record AgentProfile(URI website, URI control, String stunServers, List<String> targets) {
    AgentProfile {
        website = httpsOrigin(website.toString());
        control = controlUri(control.toString());
        stunServers = stunServers == null ? "" : stunServers.strip();
        if (stunServers.length() > 2048 || stunServers.contains("\n") || stunServers.contains("\r")) {
            throw new IllegalArgumentException("STUN 配置无效");
        }
        targets = targets.stream().map(AgentProfile::target).distinct().toList();
        if (targets.isEmpty() || targets.size() > 256) throw new IllegalArgumentException("请至少添加一个目标，最多 256 个");
        for (String target : targets) target(target);
    }

    static Path config(Path state) { return state.resolve("agent-config.properties"); }
    static Path identity(Path state) { return state.resolve("managed-identity.p12"); }
    static Path password(Path state) { return state.resolve("managed-tls.password"); }
    static Path allowlist(Path state) { return state.resolve("managed-targets"); }

    static Optional<AgentProfile> load(Path state) throws IOException {
        Path file = config(state);
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) return Optional.empty();
        AgentPrivateFiles.regular(file);
        if (Files.size(file) > 65536) throw new IOException("配置文件过大");
        Properties values = new Properties();
        try (var input = Files.newBufferedReader(file, StandardCharsets.UTF_8)) { values.load(input); }
        try {
            if (!"1".equals(values.getProperty("schema"))) throw new IllegalArgumentException("不支持的配置版本");
            return Optional.of(new AgentProfile(URI.create(values.getProperty("website", "")),
                    URI.create(values.getProperty("control", "")), values.getProperty("stun", ""),
                    Arrays.asList(values.getProperty("targets", "").split("\\n"))));
        } catch (IllegalArgumentException invalid) { throw new IOException("配置无效，请运行 configure 重新填写", invalid); }
    }

    void save(Path state) throws IOException {
        Properties values = new Properties();
        values.setProperty("schema", "1");
        values.setProperty("website", website.toString());
        values.setProperty("control", control.toString());
        values.setProperty("stun", stunServers);
        values.setProperty("targets", String.join("\n", targets));
        StringWriter writer = new StringWriter();
        values.store(writer, "JLShell Link Agent connection profile; no credentials");
        AgentPrivateFiles.write(config(state), writer.toString().getBytes(StandardCharsets.UTF_8));
        // The allowlist is derived from this profile; start regenerates it before use.
        writeTargets(state);
    }

    void writeTargets(Path state) throws IOException {
        AgentPrivateFiles.write(allowlist(state), (String.join("\n", targets) + "\n").getBytes(StandardCharsets.UTF_8));
    }

    void validateBinding(AgentIdentityStore store) throws IOException {
        var registration = store.loadRegistration();
        if (registration.isPresent() && !website.equals(httpsOrigin(registration.get().website().toString()))) {
            throw new IOException("此身份已注册到其他 Website；请使用独立配置目录，不会覆盖原注册");
        }
    }

    void applyNetwork() throws IOException {
        if (stunServers.isBlank()) { System.setProperty("jlshell.link.stun-servers", ""); return; }
        List<String> resolved = new ArrayList<>();
        for (String entry : stunServers.split(",")) {
            HostPort pair = hostPort(entry.strip());
            try {
                InetAddress address = Arrays.stream(InetAddress.getAllByName(pair.host()))
                        .filter(a -> !a.isAnyLocalAddress() && !a.isMulticastAddress())
                        .sorted(Comparator.comparingInt(a -> a instanceof Inet4Address ? 0 : 1))
                        .findFirst().orElseThrow();
                String host = address.getHostAddress();
                resolved.add((host.contains(":") ? "[" + host + "]" : host) + ":" + pair.port());
            } catch (Exception failure) { throw new IOException("STUN 服务器无法解析，请在配置菜单检查地址"); }
        }
        if (resolved.size() > 8) throw new IOException("最多配置 8 个 STUN 服务器");
        System.setProperty("jlshell.link.stun-servers", String.join(",", resolved));
    }

    static URI httpsOrigin(String value) {
        URI uri = URI.create(value.strip());
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getQuery() != null || uri.getFragment() != null || uri.getPort() == 0 || uri.getPort() > 65535
                || !(uri.getPath().isEmpty() || uri.getPath().equals("/"))) {
            throw new IllegalArgumentException("请输入 HTTPS 网站地址，不要附加 /api、查询参数或账号");
        }
        return URI.create("https://" + uri.getRawAuthority());
    }

    static URI controlUri(String value) {
        URI input = URI.create(value.strip());
        String scheme = input.getScheme();
        if (!("wss".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) || input.getHost() == null
                || input.getUserInfo() != null || input.getQuery() != null || input.getFragment() != null
                || input.getPort() == 0 || input.getPort() > 65535
                || !(input.getPath().isEmpty() || input.getPath().equals("/") || input.getPath().equals("/link/v2/control"))) {
            throw new IllegalArgumentException("请输入 Link HTTPS/WSS 地址，例如 wss://主机/link/v2/control");
        }
        return URI.create("wss://" + input.getRawAuthority() + "/link/v2/control");
    }

    static String target(String value) {
        HostPort pair = hostPort(value.strip());
        // Authoritative ACLs are exact numeric endpoints. Never silently expand a hostname/subnet.
        var endpoint = new TargetEndpoint(pair.host(), pair.port());
        String host = endpoint.address();
        return (host.contains(":") ? "[" + host + "]" : host) + ":" + endpoint.port();
    }

    static HostPort hostPort(String value) {
        int split = value.lastIndexOf(':');
        if (split < 1) throw new IllegalArgumentException("请输入 IP/主机:端口；IPv6 使用 [地址]:端口");
        String host = value.substring(0, split);
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        else if (host.contains(":")) throw new IllegalArgumentException("IPv6 地址需写成 [地址]:端口");
        if (host.isBlank() || host.contains("%") || host.contains("[") || host.contains("]") || host.contains("/") || host.contains("@") || host.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("地址无效");
        }
        int port;
        try { port = Integer.parseInt(value.substring(split + 1)); }
        catch (NumberFormatException failure) { throw new IllegalArgumentException("端口必须为数字"); }
        if (port < 1 || port > 65535) throw new IllegalArgumentException("端口范围为 1—65535");
        return new HostPort(host, port);
    }

    record HostPort(String host, int port) { }
}
