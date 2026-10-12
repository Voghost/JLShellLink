package com.jlshell.link.agent;

import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.nio.file.attribute.*;
import java.util.List;
import org.junit.jupiter.api.Test;

class EnrollmentTokenPermissionTest {
    private record Principal(String getName) implements UserPrincipal { }
    private final UserPrincipal owner = new Principal("owner");
    private AclEntry allow(UserPrincipal principal, AclEntryPermission permission) {
        return AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(principal)
                .setPermissions(permission).build();
    }
    @Test
    @org.junit.jupiter.api.condition.EnabledOnOs(org.junit.jupiter.api.condition.OS.WINDOWS)
    void checksNativeWindowsOwnerAndAcl(@org.junit.jupiter.api.io.TempDir java.nio.file.Path directory)
            throws Exception {
        var file = java.nio.file.Files.createFile(directory.resolve("test-token"));
        String user = System.getProperty("user.name");
        String domain = System.getenv("USERDOMAIN");
        String qualified = user.contains("\\") || domain == null || domain.isBlank()
                ? user : domain + "\\" + user;
        var current = file.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(qualified);
        java.nio.file.Files.setOwner(file, current);
        var acl = java.nio.file.Files.getFileAttributeView(file, AclFileAttributeView.class);
        acl.setAcl(List.of(allow(current, AclEntryPermission.READ_DATA)));
        assertDoesNotThrow(() -> AgentApplication.verifyEnrollmentTokenPermissions(file));
        var users = file.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByGroupName("Users");
        acl.setAcl(List.of(allow(current, AclEntryPermission.READ_DATA), allow(users, AclEntryPermission.READ_DATA)));
        assertThrows(IOException.class, () -> AgentApplication.verifyEnrollmentTokenPermissions(file));
    }

    @Test void acceptsOnlyOwnerReadAccess() {
        assertDoesNotThrow(() -> AgentApplication.verifyEnrollmentTokenAcl(owner,
                List.of(allow(owner, AclEntryPermission.READ_DATA))));
    }
    @Test void rejectsAnotherReaderOrWriterEvenWithOwnerRead() {
        for (var permission : List.of(AclEntryPermission.READ_DATA, AclEntryPermission.WRITE_DATA,
                AclEntryPermission.WRITE_ACL, AclEntryPermission.WRITE_OWNER)) {
            assertThrows(IOException.class, () -> AgentApplication.verifyEnrollmentTokenAcl(owner,
                    List.of(allow(owner, AclEntryPermission.READ_DATA),
                            allow(new Principal("other"), permission))));
        }
    }
    @Test void rejectsMissingOwnerReadAndEmptyAcl() {
        assertThrows(IOException.class, () -> AgentApplication.verifyEnrollmentTokenAcl(owner, List.of()));
        assertThrows(IOException.class, () -> AgentApplication.verifyEnrollmentTokenAcl(owner,
                List.of(allow(owner, AclEntryPermission.WRITE_DATA))));
    }
}
