package com.jlshell.link.core.auth;

import com.jlshell.link.core.model.AccessPolicy;
import com.jlshell.link.core.model.AccessRule;
import com.jlshell.link.core.model.TargetEndpoint;
import java.util.Objects;

/** Deny rules override allow rules; loopback requires a policy-level explicit opt-in. */
public final class AccessPolicyEvaluator {
    public boolean isAllowed(AccessPolicy policy, TargetEndpoint target) {
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(target, "target");
        if (!policy.enabled() || (target.inetAddress().isLoopbackAddress() && !policy.allowLoopback())) {
            return false;
        }
        boolean allowed = false;
        for (AccessRule rule : policy.rules()) {
            if (!rule.matches(target)) continue;
            if (rule.effect() == AccessRule.Effect.DENY) return false;
            allowed = true;
        }
        return allowed;
    }
}
