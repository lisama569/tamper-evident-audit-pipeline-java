package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.tamperevidentauditpipelinejava.config.PipelineProperties;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.AuditEvent;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.RejectReason;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.RejectedEventException;
import com.github.lisama569.tamperevidentauditpipelinejava.ingest.EventNormalizer;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 归一化：必填/类型/时间异常的拒绝原因必须可区分；默认值确定；未知字段保留。
 */
class EventNormalizerTest {

    private static final Logger log = LoggerFactory.getLogger(EventNormalizerTest.class);

    private final ObjectMapper mapper = new ObjectMapper();
    private final PipelineProperties props = new PipelineProperties();
    private final EventNormalizer normalizer = new EventNormalizer(props);

    private JsonNode json(String s) throws Exception {
        return mapper.readTree(s);
    }

    private String validJson(String overrides) throws Exception {
        String base = "{\"idempotencyKey\":\"k1\",\"source\":\"app\","
                + "\"eventType\":\"login\",\"occurredAt\":\"" + Instant.now() + "\"";
        return overrides == null || overrides.isBlank()
                ? base + "}"
                : base + "," + overrides + "}";
    }

    private void assertReject(String input, RejectReason expected, String caseName) throws Exception {
        JsonNode node = json(input);
        RejectedEventException e = assertThrows(RejectedEventException.class,
                () -> normalizer.normalize(node, null));
        assertEquals(expected, e.getReason(),
                "用例[" + caseName + "]原因应为 " + expected + " 实际 " + e.getReason());
        log.info("【拒绝用例】{} 输入={} => 判定依据 reason={} field={} msg={}",
                caseName, input.length() > 70 ? input.substring(0, 70) + "..." : input,
                e.getReason(), e.getField(), e.getMessage());
    }

    @Test
    void rejectsWithDistinctReasons() throws Exception {
        assertReject("[1,2,3]", RejectReason.PAYLOAD_NOT_OBJECT, "数组载荷");
        assertReject(validJson("\"source\":null").replace("\"source\":\"app\",", ""),
                RejectReason.MISSING_REQUIRED_FIELD, "缺 source");
        assertReject(validJson("\"source\":123"), RejectReason.TYPE_MISMATCH, "source 为数字");
        assertReject(validJson("\"eventType\":true"), RejectReason.TYPE_MISMATCH, "eventType 为布尔");
        assertReject(validJson("\"occurredAt\":\"not-a-date\""),
                RejectReason.MALFORMED_TIMESTAMP, "时间无法解析");
        assertReject(validJson("\"occurredAt\":1727337600"),
                RejectReason.TYPE_MISMATCH, "时间为裸数字");
        assertReject("{\"idempotencyKey\":\"k1\",\"source\":\"app\",\"eventType\":\"login\","
                + "\"occurredAt\":\"1960-01-01T00:00:00Z\"}",
                RejectReason.TIMESTAMP_TOO_OLD, "时间早于下限");
        assertReject(validJson("\"occurredAt\":\"" + Instant.now().plus(1, ChronoUnit.HOURS) + "\""),
                RejectReason.TIMESTAMP_IN_FUTURE, "时间超出未来偏移");
        assertReject(validJson("\"retentionDays\":0"),
                RejectReason.VALUE_OUT_OF_RANGE, "retentionDays=0");
        assertReject(validJson("\"retentionDays\":\"90\""),
                RejectReason.TYPE_MISMATCH, "retentionDays 为字符串");
        assertReject(validJson("\"idempotencyKey\":\"\"").replace("\"idempotencyKey\":\"k1\",", ""),
                RejectReason.MISSING_REQUIRED_FIELD, "空幂等键");
    }

    @Test
    void acceptsWithDeterministicDefaultsAndPreservesExtensions() throws Exception {
        JsonNode node = json(validJson("\"futureKnown\":[1,2],\"custom\":{\"a\":1}"));
        AuditEvent e = normalizer.normalize(node, null);
        assertEquals("", e.actorId(), "缺失 actorId 应归一为确定默认值空串");
        assertEquals("", e.subject());
        assertEquals(props.getDefaultRetentionDays(), e.retentionDays(),
                "缺失 retentionDays 应取配置默认值");
        assertEquals(1L, ((java.util.Map<?, ?>) e.extensions().get("custom")).get("a"));
        assertEquals(java.util.List.of(1L, 2L), e.extensions().get("futureKnown"));
        log.info("【接受用例-默认与扩展】actorId='{}' subject='{}' retentionDays={} extensions={}",
                e.actorId(), e.subject(), e.retentionDays(), e.extensions());
    }

    @Test
    void headerIdempotencyKeyFallback() throws Exception {
        String body = "{\"source\":\"app\",\"eventType\":\"login\",\"occurredAt\":\""
                + Instant.now() + "\"}";
        AuditEvent e = normalizer.normalize(json(body), "hdr-key-123");
        assertEquals("hdr-key-123", e.idempotencyKey());
        log.info("【头幂等键】载荷未提供时采用 X-Idempotency-Key={}", e.idempotencyKey());
    }
}
