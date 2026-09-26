package com.github.lisama569.tamperevidentauditpipelinejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.tamperevidentauditpipelinejava.config.PipelineProperties;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.AuditEvent;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.RejectReason;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.RejectedEventException;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 多来源事件归一化器：把原始 JSON 树校验并转换为 {@link AuditEvent}。
 *
 * <p>规则（判定结论必须可区分、可解释）：
 * <ul>
 *   <li>载荷必须是 JSON 对象；</li>
 *   <li>idempotencyKey / source / eventType / occurredAt 必填，缺字段与类型错误分别报错；</li>
 *   <li>occurredAt 必须是 ISO-8601 字符串；太早（早于配置下限）/ 太晚（超过未来偏移）分别归类；</li>
 *   <li>actorId、subject 缺失归一为 {@code ""}（确定、向后兼容）；</li>
 *   <li>retentionDays 缺失取配置默认值；提供时必须为 1..36500 的整数；</li>
 *   <li>所有未识别的顶层字段原样进入 extensions，绝不静默抹除。</li>
 * </ul>
 */
@Component
public class EventNormalizer {

    private static final java.util.Set<String> KNOWN_FIELDS = java.util.Set.of(
            "idempotencyKey", "source", "eventType", "occurredAt",
            "actorId", "subject", "retentionDays");

    private final PipelineProperties props;

    public EventNormalizer(PipelineProperties props) {
        this.props = props;
    }

    /**
     * 归一化单条事件。
     *
     * @param node             请求体中的 JSON 节点
     * @param headerIdempotencyKey 请求头 X-Idempotency-Key（可空），用于在载荷未给定时提供幂等键
     */
    public AuditEvent normalize(JsonNode node, String headerIdempotencyKey) {
        if (node == null || !node.isObject()) {
            throw new RejectedEventException(RejectReason.PAYLOAD_NOT_OBJECT, null,
                    "事件必须是 JSON 对象");
        }

        String idempotencyKey = requireString(node, "idempotencyKey", headerIdempotencyKey);
        String source = requireString(node, "source", null);
        String eventType = requireString(node, "eventType", null);
        Instant occurredAt = requireTimestamp(node);
        String actorId = optionalString(node, "actorId", "");
        String subject = optionalString(node, "subject", "");
        int retentionDays = resolveRetentionDays(node);

        Map<String, Object> extensions = new LinkedHashMap<>();
        node.fields().forEachRemaining(e -> {
            if (!KNOWN_FIELDS.contains(e.getKey())) {
                extensions.put(e.getKey(), jsonToPlain(e.getValue()));
            }
        });

        return new AuditEvent(idempotencyKey, source, eventType, occurredAt,
                actorId, subject, retentionDays, extensions);
    }

    private String requireString(JsonNode node, String field, String fallback) {
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            if (fallback != null && !fallback.isBlank()) {
                return fallback;
            }
            throw new RejectedEventException(RejectReason.MISSING_REQUIRED_FIELD, field,
                    "必填字段缺失: " + field);
        }
        if (!v.isTextual()) {
            throw new RejectedEventException(RejectReason.TYPE_MISMATCH, field,
                    "字段 " + field + " 必须是字符串，实际为 " + typeName(v));
        }
        String text = v.asText();
        if (text.isBlank()) {
            throw new RejectedEventException(RejectReason.MISSING_REQUIRED_FIELD, field,
                    "必填字段为空白: " + field);
        }
        return text;
    }

    private String optionalString(JsonNode node, String field, String defaultValue) {
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            return defaultValue;
        }
        if (!v.isTextual()) {
            throw new RejectedEventException(RejectReason.TYPE_MISMATCH, field,
                    "可选字段 " + field + " 必须是字符串，实际为 " + typeName(v));
        }
        return v.asText();
    }

    private Instant requireTimestamp(JsonNode node) {
        String field = "occurredAt";
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            throw new RejectedEventException(RejectReason.MISSING_REQUIRED_FIELD, field,
                    "必填字段缺失: " + field);
        }
        if (v.isNumber()) {
            // 明确归类为类型不匹配，而不是解析失败，原因可区分
            throw new RejectedEventException(RejectReason.TYPE_MISMATCH, field,
                    "occurredAt 必须是 ISO-8601 字符串（如 2026-09-26T08:00:00Z），不接受裸数字");
        }
        if (!v.isTextual()) {
            throw new RejectedEventException(RejectReason.TYPE_MISMATCH, field,
                    "occurredAt 必须是 ISO-8601 字符串，实际为 " + typeName(v));
        }
        Instant t;
        try {
            t = Instant.parse(v.asText());
        } catch (DateTimeParseException e) {
            throw new RejectedEventException(RejectReason.MALFORMED_TIMESTAMP, field,
                    "occurredAt 无法解析为 ISO-8601: " + v.asText());
        }
        long nowSec = Instant.now().getEpochSecond();
        if (t.getEpochSecond() < props.getMinEventTimeEpochSeconds()) {
            throw new RejectedEventException(RejectReason.TIMESTAMP_TOO_OLD, field,
                    "事件时间早于允许下限 epoch=" + props.getMinEventTimeEpochSeconds());
        }
        if (t.getEpochSecond() - nowSec > props.getMaxFutureClockSkewSeconds()) {
            throw new RejectedEventException(RejectReason.TIMESTAMP_IN_FUTURE, field,
                    "事件时间超出未来时钟偏移 " + props.getMaxFutureClockSkewSeconds() + " 秒");
        }
        return t;
    }

    private int resolveRetentionDays(JsonNode node) {
        JsonNode v = node.get("retentionDays");
        if (v == null || v.isNull()) {
            return props.getDefaultRetentionDays();
        }
        if (v.isTextual() || v.isBoolean() || v.isObject() || v.isArray() || v.isNull()) {
            throw new RejectedEventException(RejectReason.TYPE_MISMATCH, "retentionDays",
                    "retentionDays 必须是整数，实际为 " + typeName(v));
        }
        if (!v.canConvertToInt() || v.asLong() != v.asInt()) {
            throw new RejectedEventException(RejectReason.VALUE_OUT_OF_RANGE, "retentionDays",
                    "retentionDays 超出整数范围");
        }
        int d = v.asInt();
        if (d < 1 || d > 36500) {
            throw new RejectedEventException(RejectReason.VALUE_OUT_OF_RANGE, "retentionDays",
                    "retentionDays 必须在 1..36500 之间，实际 " + d);
        }
        return d;
    }

    private Object jsonToPlain(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (node.isObject()) {
            Map<String, Object> m = new LinkedHashMap<>();
            node.fields().forEachRemaining(e -> m.put(e.getKey(), jsonToPlain(e.getValue())));
            return m;
        }
        if (node.isArray()) {
            java.util.List<Object> list = new java.util.ArrayList<>();
            node.forEach(c -> list.add(jsonToPlain(c)));
            return list;
        }
        if (node.isTextual()) {
            return node.asText();
        }
        if (node.isBoolean()) {
            return node.asBoolean();
        }
        if (node.isIntegralNumber()) {
            return node.asLong();
        }
        if (node.isFloatingPointNumber()) {
            return node.asDouble();
        }
        return node.asText();
    }

    private String typeName(JsonNode v) {
        if (v.isObject()) {
            return "object";
        }
        if (v.isArray()) {
            return "array";
        }
        if (v.isTextual()) {
            return "string";
        }
        if (v.isBoolean()) {
            return "boolean";
        }
        if (v.isNumber()) {
            return "number";
        }
        return v.getNodeType().name().toLowerCase();
    }
}
