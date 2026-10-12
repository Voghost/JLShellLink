package com.jlshell.link.agent;

import java.io.*;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import com.jlshell.link.core.identity.NodeProofService;

/** Same console UI for Linux, macOS and Windows; secrets are only accepted by readPassword. */
final class AgentInteractive {
    private AgentInteractive() { }

    static int menu(Console console, Path state) throws Exception {
        requireConsole(console);
        while (true) {
            console.printf("%n╭─ JLShell Link Agent ──────────────────╮%n");
            console.printf("  1. 首次配置 / 注册%n  2. 启动网关%n  3. 查看状态%n  4. 连接诊断%n  5. 修改连接和目标%n  6. 停止网关%n  0. 退出%n");
            console.printf("配置和身份目录：%s%n", state);
            boolean registered = java.nio.file.Files.exists(state.resolve("agent.properties"))
                    && java.nio.file.Files.exists(state.resolve("agent.credential"));
            String defaultAction = registered && java.nio.file.Files.exists(AgentProfile.config(state)) ? "2" : "1";
            String action;
            try { action = read(console, "选择", defaultAction, 16); }
            catch (Cancelled cancelled) { return 0; }
            if (action.equals("0")) return 0;
            try {
                var store = new AgentIdentityStore(state);
                switch (action) {
                    case "1", "5" -> configure(console, store);
                    case "2" -> start(console, store, false);
                    case "3" -> AgentApplication.execute(new String[]{"status", "--state-dir", state.toString()}, console);
                    case "4" -> start(console, store, true);
                    case "6" -> AgentApplication.execute(new String[]{"stop", "--state-dir", state.toString()}, console);
                    default -> console.printf("请输入菜单中的数字。%n");
                }
            } catch (Cancelled cancelled) { console.printf("已取消，原注册身份保留。%n"); }
            catch (Exception failure) { console.printf("未完成：%s%n可修正配置后重试；不会重置节点身份。%n", safeMessage(failure)); }
        }
    }

    static void configure(Console console, AgentIdentityStore store) throws Exception {
        requireConsole(console);
        if (AgentServiceControl.running(store.directory())) throw new IOException("网关正在运行，请先停止后修改配置");
        boolean launch;
        try (var operation = AgentPrivateFiles.lock(store.directory())) {
            launch = configureProfile(console, store);
        }
        if (launch) start(console, store, false);
    }

    private static boolean configureProfile(Console console, AgentIdentityStore store) throws Exception {
        requireConsole(console);
        if (AgentServiceControl.running(store.directory())) throw new IOException("网关正在运行，请先停止后修改配置");
        AgentProfile previous = AgentProfile.load(store.directory()).orElse(null);
        var registration = store.loadRegistration();
        console.printf("%n配置向导：直接回车保留默认值；输入 :back 取消。%n");
        URI website;
        if (registration.isPresent()) {
            website = registration.get().website();
            console.printf("已注册到 %s；无需再次输入注册令牌。%n", website);
        } else {
            website = prompt(console, "Website HTTPS 地址", previous == null ? "" : previous.website().toString(),
                    AgentProfile::httpsOrigin);
        }
        String defaultControl = previous == null ? "wss://" + website.getRawAuthority() : previous.control().toString();
        URI control = prompt(console, "Link 服务地址（可填 HTTPS 域名）", defaultControl, AgentProfile::controlUri);
        String defaultStun = previous == null ? hostPortDefault(control) : previous.stunServers();
        String stun = read(console, "STUN 主机:UDP端口（支持域名；填 - 不使用 STUN）", defaultStun, 2048);
        if (stun.equals("-")) stun = "";
        if (!stun.isEmpty()) {
            String[] entries = stun.split(",", -1);
            if (entries.length > 8) throw new IllegalArgumentException("最多配置 8 个 STUN 服务器");
            for (String item : entries) AgentProfile.hostPort(item.strip());
        }
        console.printf("%n添加 Windows/Linux/macOS 网关能访问的目标，例如 192.0.2.10:22。%n"
                + "目标需在 Website 同时获准；配置向导不会扩大网站授权。%n");
        List<String> targets = new ArrayList<>();
        if (previous != null) console.printf("已有目标：%s%n首行直接回车可保留。%n", String.join(", ", previous.targets()));
        while (targets.size() < 256) {
            String value = read(console, "目标 IP:TCP端口（回车结束）", "", 512);
            if (value.isEmpty()) {
                if (targets.isEmpty() && previous != null) targets.addAll(previous.targets());
                if (!targets.isEmpty()) break;
                console.printf("至少填写一个精确目标。%n"); continue;
            }
            try {
                String target = AgentProfile.target(value);
                if (!targets.contains(target)) targets.add(target);
            } catch (IllegalArgumentException invalid) { console.printf("目标无效，请输入数字 IP:端口。%n"); }
        }
        var profile = new AgentProfile(website, control, stun, targets);
        profile.validateBinding(store);
        console.printf("%nWebsite：%s%nLink：%s%n目标：%s%n", website, control, String.join(", ", targets));
        if (!yes(console, "保存配置并准备节点身份？")) throw new Cancelled();
        AgentManagedIdentity.ensure(store);
        profile.save(store.directory());
        console.printf("准备完成，配置已保存；以后启动会自动读取。%n");
        if (registration.isEmpty()) {
            console.printf("请在 Website 的“注册 Java Agent”生成一次性令牌；不会保存该令牌。%n");
            UUID agentId = prompt(console, "Agent ID", "", UUID::fromString);
            char[] token = console.readPassword("一次性注册令牌（隐藏输入）：");
            if (token == null) throw new Cancelled();
            try {
                var client = new AgentEnrollmentClient(Duration.ofSeconds(10), Duration.ofSeconds(20), new NodeProofService());
                client.register(website, agentId, new String(token).strip(), AgentApplication.platform(),
                        AgentApplication.architecture(), AgentApplication.implementationVersion(), store,
                        store.loadKey().orElseThrow());
            } finally { Arrays.fill(token, '\0'); }
            console.printf("注册成功。请在 Website 核对此网关的目标授权。%n");
        }
        console.printf("下次直接使用 agent start；修改配置使用 agent configure。%n");
        return yes(console, "现在前台启动网关？");
    }

    static void start(Console console, AgentIdentityStore store, boolean diagnose) throws Exception {
        if (AgentServiceControl.running(store.directory())) throw new IOException("网关已在运行，请先停止后操作");
        try (var operation = AgentPrivateFiles.lock(store.directory())) {
            runConfigured(console, store, diagnose);
        }
    }

    private static void runConfigured(Console console, AgentIdentityStore store, boolean diagnose) throws Exception {
        AgentProfile profile = AgentProfile.load(store.directory()).orElseThrow(() ->
                new IOException("尚未配置，请先运行 configure 或菜单 1"));
        profile.validateBinding(store);
        if (store.loadRegistration().isEmpty()) throw new IOException("尚未注册，请重新进入配置向导完成注册");
        // Do not rewrite permissions or certificates from a second process while the Agent is active.
        if (AgentServiceControl.running(store.directory())) throw new IOException("网关已在运行，请先停止后再诊断或修改身份");
        AgentManagedIdentity.ensure(store);
        profile.writeTargets(store.directory());
        profile.applyNetwork();
        AgentRuntimeService.diagnose(store, profile.control(), AgentProfile.identity(store.directory()),
                AgentProfile.password(store.directory()), AgentProfile.allowlist(store.directory()));
        if (diagnose) {
            if (console != null) console.printf("本地身份与网站连接检查通过；Link 在线状态请在启动后确认。%n");
            else System.out.println("本地身份与网站连接检查通过；Link 在线状态请在启动后确认。");
            return;
        }
        String message = "正在连接服务器；保持窗口打开，按 Ctrl+C 停止。网站在线状态以实际心跳为准。";
        if (console != null) console.printf("%s%n", message); else System.out.println(message);
        AgentRuntimeService.run(store, store.directory(), profile.control(), AgentProfile.identity(store.directory()),
                AgentProfile.password(store.directory()), AgentProfile.allowlist(store.directory()), profile.website());
    }

    private static String hostPortDefault(URI uri) {
        String host = uri.getHost();
        if (host.contains(":") && !host.startsWith("[")) host = "[" + host + "]";
        return host + ":13576";
    }
    private static void requireConsole(Console console) throws IOException {
        if (console == null) throw new IOException("向导需要交互式终端。Windows 双击 agent.cmd；macOS 双击 Agent.command；Linux 运行 ./agent.sh");
    }
    private static boolean yes(Console console, String label) throws IOException {
        String value = read(console, label + " [y/N]", "n", 16);
        return value.equalsIgnoreCase("y") || value.equalsIgnoreCase("yes") || value.equals("是");
    }
    private static String read(Console console, String label, String defaultValue, int limit) throws IOException {
        String value = console.readLine("%s%s：", label, defaultValue.isEmpty() ? "" : " [" + defaultValue + "]");
        if (value == null || value.equals(":back")) throw new Cancelled();
        value = value.strip();
        if (value.length() > limit || value.chars().anyMatch(c -> Character.isISOControl(c))) throw new IOException("输入过长或包含控制字符");
        return value.isEmpty() ? defaultValue : value;
    }
    private static <T> T prompt(Console console, String label, String defaultValue,
            java.util.function.Function<String, T> parser) throws IOException {
        while (true) {
            String value = read(console, label, defaultValue, 2048);
            try { return parser.apply(value); }
            catch (IllegalArgumentException invalid) { console.printf("填写无效：%s%n", safeMessage(invalid)); }
        }
    }
    private static String safeMessage(Exception error) {
        if (error instanceof AgentEnrollmentClient.ApiException api) return "注册服务返回 HTTP " + api.statusCode() + "，请检查令牌和账号权限";
        if (error instanceof javax.net.ssl.SSLException) return "服务器 TLS 验证失败，请检查证书和系统时间";
        // Transport exceptions may contain remote responses. Only local validation messages are shown.
        if (error instanceof IOException && error.getCause() != null) return "网络或配置读取失败，请检查服务地址和连接";
        String message = error.getMessage();
        return message == null ? "操作未完成" : message;
    }
    private static final class Cancelled extends IOException {
        Cancelled() { super("已取消配置"); }
    }
}
