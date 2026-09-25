package com.jlshell.link.agent;

import com.jlshell.link.core.identity.Ed25519NodeKey;
import com.jlshell.link.core.identity.NodeProofService;
import java.io.Console;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Minimal secure CLI for preparing and enrolling a C node. Runtime service commands are added separately. */
public final class AgentApplication {
    private AgentApplication() { }

    public static void main(String[] args) {
        int exitCode = execute(args, System.console());
        if (exitCode != 0) System.exit(exitCode);
    }

    static int execute(String[] args, Console console) {
        if (args == null || args.length == 0 || "help".equals(args[0]) || "--help".equals(args[0])) {
            printUsage();
            return 0;
        }
        try {
            Options options = Options.parse(args);
            if (!Set.of("init", "status", "enroll").contains(options.command())) {
                System.err.println("未知命令：" + options.command());
                printUsage();
                return 2;
            }
            AgentIdentityStore identity = new AgentIdentityStore(options.stateDirectory());
            return switch (options.command()) {
                case "init" -> initialize(identity);
                case "status" -> status(identity);
                case "enroll" -> enroll(identity, options, console);
                default -> throw new IllegalStateException("validated command disappeared");
            };
        } catch (Exception failure) {
            String message = failure.getMessage();
            System.err.println("Agent 操作失败：" + (message == null || message.isBlank()
                    ? failure.getClass().getSimpleName() : message));
            return 1;
        }
    }

    private static int initialize(AgentIdentityStore identity) throws IOException, GeneralSecurityException {
        Ed25519NodeKey key = identity.loadOrCreateKey();
        System.out.println("节点身份已就绪");
        System.out.println("公钥指纹：" + key.fingerprint().value());
        return 0;
    }

    private static int status(AgentIdentityStore identity) throws IOException, GeneralSecurityException {
        var key = identity.loadKey();
        var registration = identity.loadRegistration();
        System.out.println("本地身份：" + (key.isPresent() ? "已初始化" : "未初始化"));
        key.ifPresent(value -> System.out.println("公钥指纹：" + value.fingerprint().value()));
        System.out.println("Website 注册：" + (registration.isPresent() ? "已注册" : "未注册"));
        registration.ifPresent(value -> {
            System.out.println("Agent ID：" + value.agentId());
            System.out.println("Website：" + value.website());
            System.out.println("节点凭据：已保存（不显示）");
        });
        System.out.println("运行状态：未启动；当前 CLI 版本尚未提供常驻服务命令");
        return 0;
    }

    private static int enroll(AgentIdentityStore identity, Options options, Console console)
            throws IOException, GeneralSecurityException, InterruptedException {
        String websiteValue = options.value("--website");
        String agentValue = options.value("--agent-id");
        if (websiteValue == null || agentValue == null) {
            throw new IllegalArgumentException("enroll 需要 --website 和 --agent-id");
        }
        if (identity.loadRegistration().isPresent()) {
            throw new IllegalStateException("该状态目录已注册；为避免覆盖现有节点身份，请先使用独立状态目录");
        }
        URI website = URI.create(websiteValue);
        UUID agentId = UUID.fromString(agentValue);
        char[] tokenChars = readEnrollmentToken(options.value("--token-file"), console);
        try {
            String token = new String(tokenChars).trim();
            Ed25519NodeKey key = identity.loadOrCreateKey();
            AgentEnrollmentClient.Registration registration = new AgentEnrollmentClient(
                    Duration.ofSeconds(10), Duration.ofSeconds(20), new NodeProofService())
                    .register(website, agentId, token, platform(), architecture(), "0.1.0-SNAPSHOT", identity, key);
            System.out.println("Agent 注册完成");
            System.out.println("Agent ID：" + registration.agentId());
            System.out.println("公钥指纹：" + registration.keyFingerprint().value());
            System.out.println("凭据有效期至：" + registration.credentialExpiresAt());
            System.out.println("状态目录：" + options.stateDirectory());
            return 0;
        } finally {
            java.util.Arrays.fill(tokenChars, '\0');
        }
    }

    private static char[] readEnrollmentToken(String tokenFile, Console console) throws IOException {
        if (tokenFile != null) {
            Path file = Path.of(tokenFile).toAbsolutePath().normalize();
            if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("token 文件必须是普通文件，不能是符号链接");
            }
            if (Files.size(file) > 4096) throw new IOException("token 文件超过 4096 字节限制");
            if (Files.getFileAttributeView(file, java.nio.file.attribute.PosixFileAttributeView.class) == null) {
                throw new IOException("当前文件系统无法验证 token 文件权限；请使用交互式终端输入");
            }
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS);
            if (permissions.stream().anyMatch(permission -> permission.name().startsWith("GROUP_")
                    || permission.name().startsWith("OTHERS_"))) {
                throw new IOException("token 文件必须仅允许当前用户访问（chmod 600）");
            }
            var expectedOwner = Files.getOwner(Path.of(System.getProperty("user.home")), LinkOption.NOFOLLOW_LINKS);
            if (!expectedOwner.equals(Files.getOwner(file, LinkOption.NOFOLLOW_LINKS))) {
                throw new IOException("token 文件必须归当前用户所有");
            }
            return Files.readString(file, java.nio.charset.StandardCharsets.UTF_8).trim().toCharArray();
        }
        if (console == null) throw new IOException("请在交互式终端输入 token，或提供权限为 600 的 --token-file");
        char[] token = console.readPassword("Website enrollment token: ");
        if (token == null) throw new IOException("未读取到 enrollment token");
        return token;
    }

    private static String platform() {
        String os = System.getProperty("os.name", "unknown").toLowerCase(java.util.Locale.ROOT);
        if (os.contains("win")) return "windows";
        if (os.contains("mac") || os.contains("darwin")) return "macos";
        if (os.contains("linux")) return "linux";
        return "unknown";
    }

    private static String architecture() {
        return System.getProperty("os.arch", "unknown").toLowerCase(java.util.Locale.ROOT);
    }

    private static void printUsage() {
        System.out.println("JLShell Link Agent CLI");
        System.out.println("  agent init [--state-dir <path>]");
        System.out.println("  agent enroll --website <https-origin> --agent-id <uuid> [--token-file <path>] [--state-dir <path>]");
        System.out.println("  agent status [--state-dir <path>]");
        System.out.println("enrollment token 不接受命令行参数；可在交互终端隐藏输入，或从当前用户独占的 600 权限文件读取。");
    }

    private record Options(String command, Map<String, String> values) {
        private static Options parse(String[] args) {
            Map<String, String> values = new HashMap<>();
            Set<String> allowed = switch (args[0]) {
                case "init", "status" -> Set.of("--state-dir");
                case "enroll" -> Set.of("--state-dir", "--website", "--agent-id", "--token-file");
                default -> Set.of("--state-dir", "--website", "--agent-id", "--token-file");
            };
            for (int i = 1; i < args.length; i++) {
                String key = args[i];
                if (!allowed.contains(key)) {
                    throw new IllegalArgumentException("未知选项：" + key);
                }
                if (++i >= args.length || args[i].startsWith("--")) {
                    throw new IllegalArgumentException("选项缺少值：" + key);
                }
                if (values.putIfAbsent(key, args[i]) != null) {
                    throw new IllegalArgumentException("选项重复：" + key);
                }
            }
            return new Options(args[0], Map.copyOf(values));
        }

        private String value(String name) { return values.get(name); }

        private Path stateDirectory() {
            String configured = value("--state-dir");
            if (configured != null) return Path.of(configured);
            return Path.of(System.getProperty("user.home"), ".jlshell-link-agent");
        }
    }
}
