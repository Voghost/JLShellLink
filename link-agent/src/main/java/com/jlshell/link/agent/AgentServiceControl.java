package com.jlshell.link.agent;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;

/** One-instance lock and owner-only stop request inside the Agent state directory. */
final class AgentServiceControl implements AutoCloseable {
    private static final java.util.Set<PosixFilePermission> OWNER_ONLY =
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    private final Path stopFile;
    private final FileChannel channel;
    private final FileLock lock;

    private AgentServiceControl(Path stopFile, FileChannel channel, FileLock lock) {
        this.stopFile = stopFile;
        this.channel = channel;
        this.lock = lock;
    }

    static AgentServiceControl acquire(Path directory) throws IOException {
        Path lockFile = directory.resolve("agent.lock");
        if (Files.isSymbolicLink(lockFile)) throw new IOException("Agent lock file cannot be a symlink");
        FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        try {
            ownerOnly(lockFile);
            FileLock lock = channel.tryLock();
            if (lock == null) throw new IOException("Agent is already running");
            Path stopFile = directory.resolve("agent.stop");
            if (Files.isSymbolicLink(stopFile)) throw new IOException("Agent stop file cannot be a symlink");
            Files.deleteIfExists(stopFile);
            return new AgentServiceControl(stopFile, channel, lock);
        } catch (OverlappingFileLockException alreadyRunning) {
            channel.close();
            throw new IOException("Agent is already running", alreadyRunning);
        } catch (IOException | RuntimeException failure) {
            channel.close();
            throw failure;
        }
    }

    static boolean running(Path directory) throws IOException {
        Path lockFile = directory.resolve("agent.lock");
        if (!Files.exists(lockFile, LinkOption.NOFOLLOW_LINKS)) return false;
        if (Files.isSymbolicLink(lockFile)) throw new IOException("Agent lock file cannot be a symlink");
        try (FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.WRITE)) {
            try (FileLock probe = channel.tryLock()) { return probe == null; }
            catch (OverlappingFileLockException runningHere) { return true; }
        }
    }

    static void requestStop(Path directory) throws IOException {
        if (!running(directory)) throw new IOException("Agent is not running");
        Path stopFile = directory.resolve("agent.stop");
        if (Files.isSymbolicLink(stopFile)) throw new IOException("Agent stop file cannot be a symlink");
        Files.writeString(stopFile, "stop\n", StandardOpenOption.CREATE_NEW);
        ownerOnly(stopFile);
    }

    boolean stopRequested() throws IOException {
        if (!Files.exists(stopFile, LinkOption.NOFOLLOW_LINKS)) return false;
        if (Files.isSymbolicLink(stopFile)) throw new IOException("Agent stop file cannot be a symlink");
        return true;
    }

    private static void ownerOnly(Path file) throws IOException {
        if (Files.getFileAttributeView(file, java.nio.file.attribute.PosixFileAttributeView.class) != null) {
            Files.setPosixFilePermissions(file, OWNER_ONLY);
        }
    }

    @Override public void close() throws IOException {
        lock.release();
        channel.close();
        Files.deleteIfExists(stopFile);
    }
}
