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
