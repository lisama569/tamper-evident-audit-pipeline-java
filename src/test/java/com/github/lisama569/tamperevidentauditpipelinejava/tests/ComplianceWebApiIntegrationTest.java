package com.github.lisama569.tamperevidentauditpipelinejava.tests;

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
 * 本轮新增 HTTP 能力：合规清除预演/执行/幂等/409 冲突、全量核验端点、state 扩展字段。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ComplianceWebApiIntegrationTest {

    private static final Logger LOG = Logger.getLogger(ComplianceWebApiIntegrationTest.class.getName());

    @TempDir
    static java.nio.file.Path tempDir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("audit.storage-dir", () -> tempDir.toString());
        registry.add("audit.auto-forward", () -> "false");
    }

    @Autowired
    private TestRestTemplate rest;

    private HttpHeaders json() {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        return h;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> post(String path, String body) {
        ResponseEntity<Map> resp = rest.postForEntity(path, new HttpEntity<>(body, json()), Map.class);
        LOG.info(() -> "[WEB] POST " + path + " -> " + resp.getStatusCode() + " " + resp.getBody());
        assertEquals(HttpStatus.OK, resp.getStatusCode(), () -> "body=" + resp.getBody());
        return resp.getBody();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> get(String path) {
        ResponseEntity<Map> resp = rest.getForEntity(path, Map.class);
        LOG.info(() -> "[WEB] GET " + path + " -> " + resp.getStatusCode() + " " + resp.getBody());
        return resp.getBody();
    }

    private long ingest(String eventId, String subject) {
        String body = "{\"source\":\"web\",\"eventId\":\"" + eventId + "\",\"eventType\":\"login\","
                + "\"occurredAt\":\"2026-09-01T10:00:00Z\",\"subject\":\"" + subject + "\"}";
        Map<String, Object> r = post("/audit/events", body);
        return ((Number) r.get("sequence")).longValue();
    }

    @Test
    void compliancePreviewExecuteVerifyStateOverHttp() {
        ingest("w1", "alice");
        ingest("w2", "bob");
        // 法律保留挡 bob
        ResponseEntity<Map> holdResp = rest.postForEntity("/audit/holds",
                new HttpEntity<>("{\"holdId\":\"hh\",\"subjectPattern\":\"bob\",\"reason\":\"freeze\"}", json()),
                Map.class);
        assertEquals(HttpStatus.OK, holdResp.getStatusCode());

        String reqBody = "{\"requestId\":\"web-1\",\"reason\":\"gdpr\",\"subject\":\"alice\"}";
        Map<String, Object> preview = post("/audit/compliance/purge/preview", reqBody);
        assertEquals(true, preview.get("dryRun"));
        assertEquals(List.of(1), preview.get("purgedSequences"));
        assertEquals(List.of(), preview.get("blockedByLegalHold"));

        // 执行 web-1：清掉 alice(seq1)
        Map<String, Object> exec1 = post("/audit/compliance/purge/execute", reqBody);
        assertEquals(List.of(1), exec1.get("purgedSequences"));
        // 再执行一次同 id：幂等，结论一致
        Map<String, Object> replay = post("/audit/compliance/purge/execute", reqBody);
        assertEquals(List.of(1), replay.get("purgedSequences"));

        // 范围请求覆盖 bob(seq2)，应被 hold 挡下；seq1 已清不计入本次
        String rangeReq = "{\"requestId\":\"web-2\",\"reason\":\"r\",\"fromSequence\":1,\"toSequence\":2}";
        Map<String, Object> exec2 = post("/audit/compliance/purge/execute", rangeReq);
        assertEquals(List.of(), exec2.get("purgedSequences"));
        assertEquals(List.of(2), exec2.get("blockedByLegalHold"));
        assertEquals(List.of(1), exec2.get("alreadyPurged"));

        // 同 id 不同选择器 → 409
        ResponseEntity<Map> conflict = rest.postForEntity("/audit/compliance/purge/execute",
                new HttpEntity<>("{\"requestId\":\"web-1\",\"reason\":\"gdpr\",\"subject\":\"bob\"}", json()),
                Map.class);
        assertEquals(HttpStatus.CONFLICT, conflict.getStatusCode());
        assertEquals("COMPLIANCE_REQUEST_CONFLICT", conflict.getBody().get("reason"));

        // 核验端点：健康
        Map<String, Object> verify = post("/audit/verify", "{}");
        assertEquals(true, verify.get("healthy"));

        // state 扩展字段
        Map<String, Object> state = get("/audit/state");
        assertEquals(false, state.get("ledgerClosed"));
        assertEquals(-1, ((Number) state.get("firstTamperedSequence")).intValue());
        assertEquals("OK", state.get("tamperEvidence"));
        assertNotNull(state.get("tamperDetail"));
        assertNotNull(state.get("frameCount"));

        // 兼容端点：全新目录 legacy=false
        Map<String, Object> compat = get("/audit/compatibility");
        assertEquals(false, compat.get("legacy"));
    }
}
