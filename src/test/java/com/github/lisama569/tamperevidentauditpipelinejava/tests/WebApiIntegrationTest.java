package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.util.Map;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * HTTP 层集成测试：200 接受、400 分类拒绝、malformed JSON 也给出 MALFORMED_JSON，重复提交返回 duplicate=true。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)

class WebApiIntegrationTest {

    private static final Logger LOG = Logger.getLogger(WebApiIntegrationTest.class.getName());

    @TempDir
    static java.nio.file.Path tempDir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("audit.storage-dir", () -> tempDir.toString());
        registry.add("audit.auto-forward", () -> "false");
    }

    @Autowired
    private TestRestTemplate rest;

    @SuppressWarnings("unchecked")
    private Map<String, Object> post(String body) {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<Map> resp = rest.postForEntity("/audit/events",
                new HttpEntity<>(body, h), Map.class);
        LOG.info(() -> "[WEB] HTTP " + resp.getStatusCode() + " body=" + resp.getBody());
        return resp.getBody();
    }

    @Test
    void acceptThenDuplicateThenReject() {
        String valid = "{\"source\":\"web\",\"eventId\":\"w-1\",\"eventType\":\"login\","
                + "\"occurredAt\":\"2026-09-01T10:00:00Z\"}";
        Map<String, Object> r1 = post(valid);
        assertEquals(true, r1.get("accepted"));
        assertEquals(false, r1.get("duplicate"));
        assertEquals(1, ((Number) r1.get("sequence")).intValue());

        Map<String, Object> r2 = post(valid);
        assertEquals(true, r2.get("accepted"));
        assertEquals(true, r2.get("duplicate"));

        Map<String, Object> r3 = post("{\"source\":\"web\"}");
        assertEquals(false, r3.get("accepted"));
        assertEquals("MISSING_REQUIRED_FIELD", r3.get("reason"));

        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<Map> bad = rest.postForEntity("/audit/events",
                new HttpEntity<>("{not-json", h), Map.class);
        assertEquals(HttpStatus.BAD_REQUEST, bad.getStatusCode());
        assertEquals("MALFORMED_JSON", bad.getBody().get("reason"));
    }
}
