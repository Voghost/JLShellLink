package com.jlshell.link.agent;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;

/** Private profile storage without changing system trust or execution policies. */
final class AgentPrivateFiles {
    private static volatile java.util.List<UserPrincipal> windowsReaders;
    private AgentPrivateFiles() { }

    static void directory(Path path) throws IOException {
        for (Path part = path.toAbsolutePath(); part != null; part = part.getParent()) {
            if (Files.isSymbolicLink(part)) throw new IOException("配置目录不能经过符号链接");
        }
        Files.createDirectories(path);
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) throw new IOException("配置目录无效");
        protect(path, true);
    }

    static void regular(Path path) throws IOException {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
            throw new IOException("配置或身份文件必须是普通文件");
        }
        if (Files.getFileAttributeView(path, PosixFileAttributeView.class) != null &&
                Files.getPosixFilePermissions(path).stream().anyMatch(p ->
                        p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"))) {
            throw new IOException("配置文件权限应为 600，请先修复权限");
        }
        if (Files.getFileAttributeView(path, PosixFileAttributeView.class) == null) {
            AclFileAttributeView acl = Files.getFileAttributeView(path, AclFileAttributeView.class);
            if (acl == null) throw new IOException("无法验证配置文件私有权限");
            var allowed = windowsReaders(path);
            for (AclEntry entry : acl.getAcl()) {
                if (entry.type() == AclEntryType.ALLOW && entry.permissions().contains(AclEntryPermission.READ_DATA)
                        && !allowed.contains(entry.principal())) {
                    throw new IOException("配置或身份文件允许其他用户读取，请先恢复私有 ACL");
                }
            }
        }
    }

    private static java.util.List<UserPrincipal> windowsReaders(Path path) throws IOException {
        var cached = windowsReaders;
        if (cached != null) return cached;
        String root = System.getenv("SystemRoot");
        if (root == null) throw new IOException("无法验证 Windows 权限");
        String command = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
                + "[Security.Principal.WindowsIdentity]::GetCurrent().Name;"
                + "foreach($sid in @('S-1-5-18','S-1-5-32-544')){"
                + "([Security.Principal.SecurityIdentifier]::new($sid)).Translate([Security.Principal.NTAccount]).Value}";
        Process process = new ProcessBuilder(Path.of(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe").toString(),
                "-NoProfile", "-NonInteractive", "-Command", command)
                .redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try {
            if (!process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)) throw new IOException("Windows 权限检查超时");
            byte[] output = process.getInputStream().readNBytes(8193);
            if (process.exitValue() != 0 || output.length > 8192) throw new IOException("Windows 权限检查失败");
            String[] names = new String(output, java.nio.charset.StandardCharsets.UTF_8).strip().split("\\R");
            if (names.length != 3) throw new IOException("Windows 权限信息无效");
            var values = new java.util.ArrayList<UserPrincipal>();
            for (String name : names) values.add(path.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(name.strip()));
            windowsReaders = java.util.List.copyOf(values);
            return windowsReaders;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt(); throw new IOException("Windows 权限检查中断", interrupted);
        } finally { if (process.isAlive()) process.destroyForcibly(); }
    }

    static void write(Path path, byte[] bytes) throws IOException {
        directory(path.toAbsolutePath().getParent());
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) regular(path);
        Path temp = Files.createTempFile(path.getParent(), ".agent-config-", ".tmp");
        try {
            protect(temp, false);
            try (var channel = java.nio.channels.FileChannel.open(temp, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                var buffer = java.nio.ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) channel.write(buffer);
                channel.force(true);
            }
            try { Files.move(temp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
            catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING);
            }
            protect(path, false);
        } finally { Files.deleteIfExists(temp); }
    }

    private static void protect(Path path, boolean directory) throws IOException {
        if (Files.getFileAttributeView(path, PosixFileAttributeView.class) != null) {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(directory ? "rwx------" : "rw-------"));
            return;
        }
        AclFileAttributeView acl = Files.getFileAttributeView(path, AclFileAttributeView.class);
        if (acl == null) throw new IOException("无法验证此文件系统的私有权限");
        var owner = windowsReaders(path).getFirst();
        var builder = AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(owner)
                .setPermissions(EnumSet.allOf(AclEntryPermission.class));
        if (directory) builder.setFlags(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT);
        var entries = List.of(builder.build());
        acl.setAcl(entries);
        // The standard Java ACL API cannot express SE_DACL_PROTECTED. Remove inherited
        // grants using the fixed Windows utility, then retain only the explicit owner rule.
        String root = System.getenv("SystemRoot");
        if (root == null) throw new IOException("无法保护 Windows 私有目录");
        Process process = new ProcessBuilder(Path.of(root, "System32", "icacls.exe").toString(),
                path.toAbsolutePath().toString(), "/inheritance:r")
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try {
            if (!process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS) || process.exitValue() != 0) {
                throw new IOException("无法关闭配置目录的继承权限");
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt(); throw new IOException("Windows 权限设置中断", interrupted);
        } finally { if (process.isAlive()) process.destroyForcibly(); }
        acl.setAcl(entries);
    }
}
