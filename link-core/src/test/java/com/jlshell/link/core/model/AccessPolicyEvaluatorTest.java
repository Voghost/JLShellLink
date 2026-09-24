package com.jlshell.link.core.model;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jlshell.link.core.auth.AccessPolicyEvaluator;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AccessPolicyEvaluatorTest {
    private final AccessPolicyEvaluator evaluator = new AccessPolicyEvaluator();

    @Test
    void denyOverridesCidrAllowAndPortsStayScoped() {
        AccessPolicy policy = new AccessPolicy(true, false, 4, List.of(
                new AccessRule(AccessRule.Effect.ALLOW, CidrBlock.parse("192.168.31.0/24"), Set.of(22, 443)),
                new AccessRule(AccessRule.Effect.DENY, CidrBlock.exact("192.168.31.9"), Set.of())));

        assertTrue(evaluator.isAllowed(policy, new TargetEndpoint("192.168.31.8", 22)));
        assertFalse(evaluator.isAllowed(policy, new TargetEndpoint("192.168.31.8", 80)));
        assertFalse(evaluator.isAllowed(policy, new TargetEndpoint("192.168.31.9", 22)));
        assertFalse(evaluator.isAllowed(policy, new TargetEndpoint("192.168.32.8", 22)));
    }

    @Test
    void loopbackNeedsPolicyLevelOptIn() {
        AccessRule allow = new AccessRule(AccessRule.Effect.ALLOW, CidrBlock.exact("127.0.0.1"), Set.of(22));
        assertFalse(evaluator.isAllowed(new AccessPolicy(true, false, 1, List.of(allow)),
                new TargetEndpoint("127.0.0.1", 22)));
        assertTrue(evaluator.isAllowed(new AccessPolicy(true, true, 2, List.of(allow)),
                new TargetEndpoint("127.0.0.1", 22)));
    }

    @Test
    void hostnamesAndAmbiguousIpv4AreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new TargetEndpoint("example.com", 22));
        assertThrows(IllegalArgumentException.class, () -> new TargetEndpoint("127.000.0.1", 22));
        assertThrows(IllegalArgumentException.class, () -> new TargetEndpoint("fe80::1%en0", 22));
    }
}
