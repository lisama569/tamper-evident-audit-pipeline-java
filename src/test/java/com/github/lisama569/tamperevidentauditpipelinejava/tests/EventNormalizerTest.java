package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.tamperevidentauditpipelinejava.ingest.EventNormalizer;
import com.github.lisama569.tamperevidentauditpipelinejava.ingest.NormalizedEvent;
import com.github.lisama569.tamperevidentauditpipelinejava.ingest.ValidationException;
import com.github.lisama569.tamperevidentauditpipelinejava.model.RejectReason;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

import java.time.Instant;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 字段兼容与拒绝原因分类测试：每条用例打印输入、判定依据与最终状态。
 */
class EventNormalizerTest {

    private static final Logger LOG = Logger.getLogger(EventNormalizerTest.class.getName());
    private final ObjectMapper mapper = new ObjectMapper();
    private final EventNormalizer normalizer = new EventNormalizer(60_000);

    private JsonNode json(String s) {
        try {
            return mapper.readTree(s);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void assertReject(String input, RejectReason expected, TestInfo info) {
        JsonNode node = json(input);
        ValidationException ex = assertThrows(ValidationException.class, () -> normalizer.normalize(node));
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=" + input
                + " 判定=拒绝 reason=" + ex.getReason() + " 依据=" + ex.getMessage()
                + " 最终状态=REJECTED");
        assertEquals(expected, ex.getReason());
    }

    @Test
    void validEventWithDefaultsAndUnknownFields(TestInfo info) {
        String input = """
                {"source":"web","eventId":"e1","eventType":"login",
                 "occurredAt":"2026-09-01T10:00:00Z","device":"mobile"}""";
        NormalizedEvent e = normalizer.normalize(json(input));
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=" + input
                + " 判定=通过 severity默认=" + e.severity() + " subject默认='" + e.subject() + "'"
                + " 未知字段保留 extensions.device=" + e.extensions().get("device").asText()
                + " 最终状态=ACCEPTED");
        assertEquals("web", e.source());
        assertEquals("INFO", e.severity());
        assertEquals("", e.subject());
        assertEquals("mobile", e.extensions().get("device").asText());
        assertEquals(Instant.parse("2026-09-01T10:00:00Z").toEpochMilli(), e.occurredAtMs());
    }

    @Test
    void unknownFieldsInsideExtensionsArePreserved(TestInfo info) {
        String input = """
                {"source":"web","eventId":"e2","eventType":"login",
                 "occurredAt":1780000000000,"extensions":{"custom":{"a":1}},"x":"y"}""";
        NormalizedEvent e = normalizer.normalize(json(input));
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=" + input
                + " 判定=通过 extensions=" + e.extensions() + " 最终状态=ACCEPTED");
        assertEquals(1, e.extensions().path("custom").path("a").asInt());
        assertEquals("y", e.extensions().path("x").asText());
    }

    @Test
    void rejectMissingRequired(TestInfo info) {
        assertReject("{\"source\":\"web\",\"eventId\":\"e3\",\"eventType\":\"login\"}",
                RejectReason.MISSING_REQUIRED_FIELD, info);
    }

    @Test
    void rejectBlankRequired(TestInfo info) {
        assertReject("{\"source\":\"  \",\"eventId\":\"e4\",\"eventType\":\"login\",\"occurredAt\":1}",
                RejectReason.MISSING_REQUIRED_FIELD, info);
    }

    @Test
    void rejectTypeMismatch(TestInfo info) {
        assertReject("{\"source\":123,\"eventId\":\"e5\",\"eventType\":\"login\",\"occurredAt\":1}",
                RejectReason.FIELD_TYPE_MISMATCH, info);
    }

    @Test
    void rejectTimestampTypeMismatch(TestInfo info) {
        assertReject("{\"source\":\"s\",\"eventId\":\"e6\",\"eventType\":\"t\",\"occurredAt\":true}",
                RejectReason.FIELD_TYPE_MISMATCH, info);
    }

    @Test
    void rejectUnparseableTimestamp(TestInfo info) {
        assertReject("{\"source\":\"s\",\"eventId\":\"e7\",\"eventType\":\"t\",\"occurredAt\":\"not-a-date\"}",
                RejectReason.INVALID_TIMESTAMP, info);
    }

    @Test
    void rejectNegativeEpoch(TestInfo info) {
        assertReject("{\"source\":\"s\",\"eventId\":\"e8\",\"eventType\":\"t\",\"occurredAt\":-1}",
                RejectReason.INVALID_TIMESTAMP, info);
    }

    @Test
    void rejectFutureTimestamp(TestInfo info) {
        String input = "{\"source\":\"s\",\"eventId\":\"e9\",\"eventType\":\"t\",\"occurredAt\":"
                + (System.currentTimeMillis() + 5 * 60_000) + "}";
        assertReject(input, RejectReason.SUSPICIOUS_TIMESTAMP, info);
    }

    @Test
    void rejectNonObjectBody(TestInfo info) {
        ValidationException ex = assertThrows(ValidationException.class,
                () -> normalizer.normalize(json("[1,2]")));
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=[1,2]"
                + " 判定=拒绝 reason=" + ex.getReason() + " 最终状态=REJECTED");
        assertEquals(RejectReason.MALFORMED_JSON, ex.getReason());
    }

    @Test
    void idempotencyKeyIsStable(TestInfo info) {
        String k1 = EventNormalizer.idempotencyKey("web", "e1");
        String k2 = EventNormalizer.idempotencyKey("web", "e1");
        String k3 = EventNormalizer.idempotencyKey("api", "e1");
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定=幂等键稳定 k=" + k1
                + " 不同source区分=" + !k1.equals(k3));
        assertEquals(k1, k2);
        assertNotEquals(k1, k3);
        assertEquals(64, k1.length());
    }
}
