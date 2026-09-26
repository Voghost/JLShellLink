package com.jlshell.link.core.signal;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.NodeRole;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Strict, bounded JSON mapping for the small control-channel message vocabulary. */
public final class ControlSignalJsonCodec {
    private static final int MAX_JSON_BYTES = 65_536;

    public Hello decodeHello(String json) {
        Map<String, Object> value = parse(json);
        try {
            requireType(value, "HELLO");
            requireSentAt(value);
            NodeRole role = switch (JSONObjectUtils.getString(value, "role")) {
                case "client" -> NodeRole.CLIENT;
                case "agent" -> NodeRole.AGENT;
                default -> throw new IllegalArgumentException("invalid control role");
            };
            List<String> capabilities = stringList(value, "capabilities", 32);
            return new Hello(role, UUID.fromString(JSONObjectUtils.getString(value, "nodeId")),
                    new NodeKeyFingerprint(JSONObjectUtils.getString(value, "keyFingerprint")),
                    JSONObjectUtils.getString(value, "minProtocol"),
                    JSONObjectUtils.getString(value, "maxProtocol"), capabilities);
        } catch (ParseException | IllegalArgumentException invalid) {
            throw new IllegalArgumentException("invalid HELLO message", invalid);
        }
    }

    public ControlSignal decodeSignal(String json) {
        return decode(json, false);
    }

    public ControlSignal decodeServerSignal(String json) {
        return decode(json, true);
    }

    private ControlSignal decode(String json, boolean acceptInvite) {
        Map<String, Object> value = parse(json);
        try {
            requireSentAt(value);
            String type = JSONObjectUtils.getString(value, "type");
            UUID messageId = UUID.fromString(JSONObjectUtils.getString(value, "messageId"));
            LinkSessionId sessionId = LinkSessionId.parse(JSONObjectUtils.getString(value, "sessionId"));
            long generation = JSONObjectUtils.getLong(value, "generation");
            return switch (type) {
                case "ICE_CANDIDATE" -> new ControlSignal.IceCandidate(messageId, sessionId, generation,
                        UUID.fromString(JSONObjectUtils.getString(value, "candidateId")),
                        ControlSignal.CandidateType.valueOf(JSONObjectUtils.getString(value, "candidateType")),
                        ControlSignal.Transport.valueOf(JSONObjectUtils.getString(value, "transport")),
                        parseNumericAddress(JSONObjectUtils.getString(value, "address")),
                        JSONObjectUtils.getInt(value, "port"), JSONObjectUtils.getLong(value, "priority"),
                        JSONObjectUtils.getString(value, "foundation"));
                case "ICE_END" -> new ControlSignal.IceEnd(messageId, sessionId, generation);
                case "PATH_READY" -> new ControlSignal.PathReady(messageId, sessionId, generation,
                        ControlSignal.Path.valueOf(JSONObjectUtils.getString(value, "path")),
                        optionalUuid(value, "localCandidateId"), optionalUuid(value, "remoteCandidateId"));
                case "SESSION_INVITE" -> {
                    if (!acceptInvite) throw new IllegalArgumentException("SESSION_INVITE is server-only");
                    yield new ControlSignal.SessionInvite(messageId, sessionId, generation,
                            UUID.fromString(JSONObjectUtils.getString(value, "agentId")),
                            UUID.fromString(JSONObjectUtils.getString(value, "clientDeviceId")),
                            new NodeKeyFingerprint(JSONObjectUtils.getString(value, "agentKeyFingerprint")),
                            new NodeKeyFingerprint(JSONObjectUtils.getString(value, "clientKeyFingerprint")),
                            JSONObjectUtils.getLong(value, "policyVersion"),
                            Instant.parse(JSONObjectUtils.getString(value, "expiresAt")));
                }
                case "SESSION_REVOKED" -> {
                    if (!acceptInvite) throw new IllegalArgumentException("SESSION_REVOKED is server-only");
                    yield new ControlSignal.SessionRevoked(messageId, sessionId, generation);
                }
                default -> throw new IllegalArgumentException("unknown control signal type");
            };
        } catch (ParseException | IllegalArgumentException invalid) {
            throw new IllegalArgumentException("invalid control signal", invalid);
        }
    }

    public String encode(ControlSignal signal) {
        Map<String, Object> value = base(signal instanceof ControlSignal.SessionInvite ? "SESSION_INVITE"
                : signal instanceof ControlSignal.SessionRevoked ? "SESSION_REVOKED"
                : signal instanceof ControlSignal.IceCandidate ? "ICE_CANDIDATE"
                : signal instanceof ControlSignal.IceEnd ? "ICE_END" : "PATH_READY",
                signal.messageId(), signal.sessionId(), signal.generation());
        if (signal instanceof ControlSignal.SessionInvite invite) {
            value.put("agentId", invite.agentId().toString());
            value.put("clientDeviceId", invite.clientDeviceId().toString());
            value.put("agentKeyFingerprint", invite.agentKeyFingerprint().value());
            value.put("clientKeyFingerprint", invite.clientKeyFingerprint().value());
            value.put("policyVersion", invite.policyVersion());
            value.put("expiresAt", invite.expiresAt().toString());
        } else if (signal instanceof ControlSignal.IceCandidate candidate) {
            value.put("candidateId", candidate.candidateId().toString());
            value.put("candidateType", candidate.candidateType().name());
            value.put("transport", candidate.transport().name());
            value.put("address", candidate.address().getHostAddress());
            value.put("port", candidate.port());
            value.put("priority", candidate.priority());
            value.put("foundation", candidate.foundation());
        } else if (signal instanceof ControlSignal.PathReady ready) {
            value.put("path", ready.path().name());
            if (ready.localCandidateId() != null) {
                value.put("localCandidateId", ready.localCandidateId().toString());
                value.put("remoteCandidateId", ready.remoteCandidateId().toString());
            }
        }
        return JSONObjectUtils.toJSONString(value);
    }

    public String encodeReady(UUID nodeId, long connectionGeneration) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("type", "READY");
        value.put("protocol", "link-v2");
        value.put("nodeId", nodeId.toString());
        value.put("connectionGeneration", connectionGeneration);
        value.put("sentAt", Instant.now().toString());
        return JSONObjectUtils.toJSONString(value);
    }

    public String encodeError(String code) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("type", "ERROR");
        value.put("code", code);
        value.put("sentAt", Instant.now().toString());
        return JSONObjectUtils.toJSONString(value);
    }

    private static Map<String, Object> base(String type, UUID messageId, LinkSessionId sessionId,
                                            long generation) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("type", type);
        value.put("messageId", messageId.toString());
        value.put("sessionId", sessionId.value().toString());
        value.put("generation", generation);
        value.put("sentAt", Instant.now().toString());
        return value;
    }

    private static Map<String, Object> parse(String json) {
        if (json == null || json.isBlank() || json.length() > MAX_JSON_BYTES) {
            throw new IllegalArgumentException("control message size is invalid");
        }
        try {
            return JSONObjectUtils.parse(json, MAX_JSON_BYTES);
        } catch (ParseException invalid) {
            throw new IllegalArgumentException("control message is not valid JSON", invalid);
        }
    }

    private static void requireType(Map<String, Object> value, String expected) throws ParseException {
        if (!expected.equals(JSONObjectUtils.getString(value, "type"))) {
            throw new IllegalArgumentException("unexpected control message type");
        }
    }

    private static void requireSentAt(Map<String, Object> value) throws ParseException {
        try {
            Instant.parse(JSONObjectUtils.getString(value, "sentAt"));
        } catch (java.time.DateTimeException invalid) {
            throw new IllegalArgumentException("control message sentAt is invalid", invalid);
        }
    }

    private static List<String> stringList(Map<String, Object> value, String name, int maxCount)
            throws ParseException {
        List<Object> raw = JSONObjectUtils.getJSONArray(value, name);
        if (raw.size() > maxCount) throw new IllegalArgumentException("too many control capabilities");
        List<String> result = new ArrayList<>(raw.size());
        for (Object entry : raw) {
            if (!(entry instanceof String text) || text.length() > 64
                    || !text.matches("[a-z][a-z0-9-]{0,63}")) {
                throw new IllegalArgumentException("invalid control capability");
            }
            result.add(text);
        }
        return List.copyOf(result);
    }

    private static UUID optionalUuid(Map<String, Object> value, String name) throws ParseException {
        Object raw = value.get(name);
        if (raw == null) return null;
        if (!(raw instanceof String text)) throw new IllegalArgumentException("missing " + name);
        return UUID.fromString(text);
    }

    private static InetAddress parseNumericAddress(String value) {
        if (value.indexOf(':') >= 0) {
            if (!value.matches("[0-9A-Fa-f:.]+") || value.indexOf('%') >= 0) {
                throw new IllegalArgumentException("candidate address must be a numeric IP");
            }
            try {
                InetAddress address = InetAddress.getByName(value);
                if (!(address instanceof Inet6Address)) throw new IllegalArgumentException("invalid IPv6 candidate");
                return address;
            } catch (UnknownHostException invalid) {
                throw new IllegalArgumentException("invalid IPv6 candidate", invalid);
            }
        }
        String[] octets = value.split("\\.", -1);
        if (octets.length != 4) throw new IllegalArgumentException("candidate address must be a numeric IP");
        byte[] address = new byte[4];
        for (int i = 0; i < octets.length; i++) {
            if (!octets[i].matches("0|[1-9][0-9]{0,2}")) {
                throw new IllegalArgumentException("invalid IPv4 candidate");
            }
            int parsed = Integer.parseInt(octets[i]);
            if (parsed > 255) throw new IllegalArgumentException("invalid IPv4 candidate");
            address[i] = (byte) parsed;
        }
        try {
            return InetAddress.getByAddress(address);
        } catch (UnknownHostException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    public record Hello(NodeRole role, UUID nodeId, NodeKeyFingerprint keyFingerprint,
                        String minProtocol, String maxProtocol, List<String> capabilities) { }
}
