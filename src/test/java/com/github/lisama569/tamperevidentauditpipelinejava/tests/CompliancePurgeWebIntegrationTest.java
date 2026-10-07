package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * HTTP 层：合规清除预演/执行/幂等/冲突 409、/audit/verify 核验、/audit/state 兼容与破坏状态。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CompliancePurgeWebIntegrationTest {

    private static final Logger LOG = Logger.getLogger(CompliancePurgeWebIntegrationTest.class.getName());
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir
    static java.nio.file.Path tempDir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("audit.storage-dir", () -> tempDir.toString());
        registry.add("audit.auto-forward", () -> "false");
    }

    @Autowired
    private TestRestTemplate rest;

    private HttpHeaders jsonHeaders() {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        return h;
    }

    @SuppressWarnings("rawtypes")
    private ResponseEntity<Map> post(String path, String body) {
        ResponseEntity<Map> resp = rest.postForEntity(path, new HttpEntity<>(body, jsonHeaders()), Map.class);
        LOG.info(() -> "[WEB] POST " + path + " -> " + resp.getStatusCode() + " " + resp.getBody());
        return resp;
    }

    private String eventJson(String eventId, String subject) {
        return "{\"source\":\"web\",\"eventId\":\"" + eventId + "\",\"eventType\":\"login\","
                + "\"occurredAt\":\"2026-09-01T10:00:00Z\",\"subject\":\"" + subject + "\"}";
    }

    @SuppressWarnings("unchecked")
    @Test
    void compliancePurgeLifecycleOverHttp() {
        post("/audit/events", eventJson("e1", "alice"));
        post("/audit/events", eventJson("e2", "bob"));
        post("/audit/events", eventJson("e3", "alice"));

        // 1) 预演
        String preview = "{\"requestId\":\"r1\",\"reason\":\"GDPR\",\"fromSeqInclusive\":1,"
                + "\"toSeqInclusive\":3,\"dryRun\":true}";
        ResponseEntity<Map> pr = post("/audit/compliance/purges", preview);
        assertEquals(HttpStatus.OK, pr.getStatusCode());
        assertEquals(Boolean.TRUE, pr.getBody().get("dryRun"));
        assertEquals(Boolean.FALSE, pr.getBody().get("idempotentReplay"));
        List<Number> previewPurged = (List<Number>) pr.getBody().get("purgedSequences");
        assertEquals(3, previewPurged.size());

        // 预演后数据仍可读
        ResponseEntity<Map> state0 = rest.getForEntity("/audit/state", Map.class);
        assertEquals(3, ((Number) state0.getBody().get("eventCount")).intValue());

        // 2) 正式执行：清单一致
        String exec = "{\"requestId\":\"r1\",\"reason\":\"GDPR\",\"fromSeqInclusive\":1,\"toSeqInclusive\":3}";
        ResponseEntity<Map> er = post("/audit/compliance/purges", exec);
        assertEquals(HttpStatus.OK, er.getStatusCode());
        List<Number> execPurged = (List<Number>) er.getBody().get("purgedSequences");
        assertEquals(List.of(1L, 2L, 3L), execPurged.stream().map(Number::longValue).toList());

        // 3) 幂等重放
        ResponseEntity<Map> again = post("/audit/compliance/purges", exec);
        assertEquals(HttpStatus.OK, again.getStatusCode());
        assertEquals(Boolean.TRUE, again.getBody().get("idempotentReplay"));
        List<Number> againPurged = (List<Number>) again.getBody().get("purgedSequences");
        assertEquals(execPurged.stream().map(Number::longValue).toList(),
                againPurged.stream().map(Number::longValue).toList());

        // 4) 同 ID 不同请求体 → 409
        String conflict = "{\"requestId\":\"r1\",\"reason\":\"GDPR\",\"fromSeqInclusive\":1,\"toSeqInclusive\":2}";
        ResponseEntity<Map> cr = post("/audit/compliance/purges", conflict);
        assertEquals(HttpStatus.CONFLICT, cr.getStatusCode());
        assertEquals("DUPLICATE_REQUEST_ID_CONFLICT", cr.getBody().get("reason"));

        // 5) 核验健康 + 状态中清除来源统计
        ResponseEntity<Map> vr = post("/audit/verify", "{}");
        assertEquals(Boolean.TRUE, vr.getBody().get("healthy"));
        ResponseEntity<Map> st = rest.getForEntity("/audit/state", Map.class);
        assertEquals(Boolean.TRUE, st.getBody().get("healthy"));
        assertEquals(Boolean.FALSE, st.getBody().get("ledgerClosed"));
        assertEquals(3, ((Number) st.getBody().get("purgedByCompliance")).intValue());
        assertEquals(0, ((Number) st.getBody().get("purgedByRetention")).intValue());
        LOG.info(() -> "[CASE compliancePurgeLifecycleOverHttp] 最终状态=预演/执行/幂等/409/核验/state 全部符合预期");
    }

    @SuppressWarnings("unchecked")
    @Test
    void missingRequestIdRejectedAsBadRequest() {
        ResponseEntity<Map> r = post("/audit/compliance/purges",
                "{\"reason\":\"x\",\"fromSeqInclusive\":1}");
        assertEquals(HttpStatus.BAD_REQUEST, r.getStatusCode());
        LOG.info(() -> "[CASE missingRequestIdRejectedAsBadRequest] -> " + r.getStatusCode());
    }
}
