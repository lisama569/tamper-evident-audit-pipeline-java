package com.github.lisama569.tamperevidentauditpipelinejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.tamperevidentauditpipelinejava.model.RejectReason;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Set;

/**
 * 多来源原始 JSON 事件的解析、校验、默认值填充与归一化。
 *
 * <p>规则（确定性、向后兼容）：
 * <ul>
 *   <li>必填：source / eventId / eventType 为非空字符串；occurredAt 为数字(epoch 毫秒)或 ISO-8601 字符串；
 *       缺失 → MISSING_REQUIRED_FIELD；存在但类型不符 → FIELD_TYPE_MISMATCH；时间无法解析 → INVALID_TIMESTAMP。</li>
 *   <li>occurredAt 早于 1970-01-01 → INVALID_TIMESTAMP；晚于 now+skew → SUSPICIOUS_TIMESTAMP（不静默丢弃）。</li>
 *   <li>可选：severity 缺省/空白 → "INFO"（大写归一）；subject 缺省 → ""。</li>
 *   <li>未知顶层字段不抹掉：连同可选的 extensions 对象一并合并保留到 extensions。</li>
 * </ul>
 */
public class EventNormalizer {

    static final Set<String> KNOWN_FIELDS =
            Set.of("source", "eventId", "eventtype", "occurredat", "severity", "subject", "extensions");

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final long maxFutureSkewMs;

    public EventNormalizer(long maxFutureSkewMs) {
        this.maxFutureSkewMs = maxFutureSkewMs;
    }

    public NormalizedEvent normalize(JsonNode raw) {
        if (raw == null || !raw.isObject()) {
            throw new ValidationException(RejectReason.MALFORMED_JSON, "事件体必须是 JSON 对象");
        }
        String source = requireNonBlankString(raw, "source");
        String eventId = requireNonBlankString(raw, "eventId");
        String eventType = requireNonBlankString(raw, "eventType");
        long occurredAtMs = parseTimestamp(raw.get("occurredAt"));

        JsonNode sevNode = raw.get("severity");
        String severity = "INFO";
        if (sevNode != null && !sevNode.isNull()) {
            if (!sevNode.isTextual()) {
                throw new ValidationException(RejectReason.FIELD_TYPE_MISMATCH,
                        "severity 必须是字符串，实际类型: " + sevNode.getNodeType());
            }
            String s = sevNode.asText().trim();
            if (!s.isEmpty()) {
                severity = s.toUpperCase(java.util.Locale.ROOT);
            }
        }

        JsonNode subjNode = raw.get("subject");
        String subject = "";
        if (subjNode != null && !subjNode.isNull()) {
            if (!subjNode.isTextual()) {
                throw new ValidationException(RejectReason.FIELD_TYPE_MISMATCH,
                        "subject 必须是字符串，实际类型: " + subjNode.getNodeType());
            }
            subject = subjNode.asText();
        }

        ObjectNode extensions = MAPPER.createObjectNode();
        JsonNode extNode = raw.get("extensions");
        if (extNode != null && !extNode.isNull()) {
            if (!extNode.isObject()) {
                throw new ValidationException(RejectReason.FIELD_TYPE_MISMATCH,
                        "extensions 必须是 JSON 对象，实际类型: " + extNode.getNodeType());
            }
            extNode.fields().forEachRemaining(e -> extensions.set(e.getKey(), e.getValue()));
        }
        raw.fields().forEachRemaining(e -> {
            if (!KNOWN_FIELDS.contains(e.getKey().toLowerCase(java.util.Locale.ROOT))) {
                extensions.set(e.getKey(), e.getValue());
            }
        });

        return new NormalizedEvent(source, eventId, eventType, occurredAtMs, severity, subject, extensions);
    }

    private String requireNonBlankString(JsonNode raw, String field) {
        JsonNode node = raw.get(field);
        if (node == null || node.isNull()) {
            throw new ValidationException(RejectReason.MISSING_REQUIRED_FIELD, "缺少必填字段: " + field);
        }
        if (!node.isTextual()) {
            throw new ValidationException(RejectReason.FIELD_TYPE_MISMATCH,
                    "字段 " + field + " 必须是字符串，实际类型: " + node.getNodeType());
        }
        String value = node.asText().trim();
        if (value.isEmpty()) {
            throw new ValidationException(RejectReason.MISSING_REQUIRED_FIELD, "必填字段不能为空: " + field);
        }
        return value;
    }

    private long parseTimestamp(JsonNode node) {
        if (node == null || node.isNull()) {
            throw new ValidationException(RejectReason.MISSING_REQUIRED_FIELD, "缺少必填字段: occurredAt");
        }
        long millis;
        if (node.isNumber()) {
            millis = node.asLong();
        } else if (node.isTextual()) {
            String text = node.asText().trim();
            try {
                millis = Instant.parse(text).toEpochMilli();
            } catch (DateTimeParseException e) {
                throw new ValidationException(RejectReason.INVALID_TIMESTAMP,
                        "occurredAt 不是合法的 ISO-8601 时间: " + text);
            }
        } else {
            throw new ValidationException(RejectReason.FIELD_TYPE_MISMATCH,
                    "occurredAt 必须是 epoch 毫秒数字或 ISO-8601 字符串，实际类型: " + node.getNodeType());
        }
        if (millis < 0L) {
            throw new ValidationException(RejectReason.INVALID_TIMESTAMP,
                    "occurredAt 不能早于 1970-01-01T00:00:00Z: " + millis);
        }
        long now = System.currentTimeMillis();
        if (millis > now + maxFutureSkewMs) {
            throw new ValidationException(RejectReason.SUSPICIOUS_TIMESTAMP,
                    "occurredAt 超出允许的未来时钟偏移 " + maxFutureSkewMs + "ms: " + millis + " > now " + now);
        }
        return millis;
    }

    /** 稳定幂等键：sha256(source + ':' + eventId)，十六进制。 */
    public static String idempotencyKey(String source, String eventId) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest((source + ":" + eventId).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }
}
