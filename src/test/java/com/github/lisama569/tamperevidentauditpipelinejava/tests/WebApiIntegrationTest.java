package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.file.Path;
import java.time.Instant;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * 端到端：REST 批量接入（接受/重复/拒绝原因可区分）、查询、健康状态。
 * 使用一次性临时目录作为留存根目录，避免与上下文中的存储句柄相互干扰。
 */
@SpringBootTest
@AutoConfigureMockMvc
class WebApiIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(WebApiIntegrationTest.class);

    @TempDir
    static Path tempDir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("audit.storage-dir", () -> tempDir.resolve("web").toString());
        registry.add("audit.retry-on-startup", () -> "false");
    }

    @Autowired
    private MockMvc mvc;

    private static String nowIso() {
        return Instant.now().toString();
    }

    @Test
    void batchIngest_acceptedDuplicateRejected_distinct() throws Exception {
        String ts = nowIso();
        String body = """
                [
                  {"idempotencyKey":"k1","source":"app","eventType":"login","occurredAt":"%s","deviceId":"d1"},
                  {"idempotencyKey":"k1","source":"app","eventType":"login","occurredAt":"%s"},
                  {"idempotencyKey":"k2","source":"app","eventType":"login","occurredAt":"not-a-date"}
                ]
                """.formatted(ts, ts);
        String resp = mvc.perform(post("/api/audit/events").contentType("application/json").content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accepted").value(1))
                .andExpect(jsonPath("$.duplicate").value(1))
                .andExpect(jsonPath("$.rejected").value(1))
                .andExpect(jsonPath("$.results[2].reason").value("MALFORMED_TIMESTAMP"))
                .andReturn().getResponse().getContentAsString();
        log.info("【批量接入】输入=3条(含同键重复+坏时间) 判定=1 ACCEPTED/1 DUPLICATE/1 REJECTED 响应={}", resp);

        mvc.perform(get("/api/audit/records/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.event.extensions.deviceId").value("d1"));

        mvc.perform(post("/api/audit/events")
                        .header("X-Idempotency-Key", "hdr-key")
                        .contentType("application/json")
                        .content("{\"source\":\"app\",\"eventType\":\"login\",\"occurredAt\":\"" + nowIso() + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accepted").value(1));

        mvc.perform(get("/api/audit/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sealed").value(false))
                .andExpect(jsonPath("$.lastSeq").value(2));
        log.info("【健康状态】sealed=false lastSeq=2，未知字段与头幂等键均符合预期");
    }

    @Test
    void malformedJson_is400WithCode() throws Exception {
        mvc.perform(post("/api/audit/events").contentType("application/json").content("{not json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("MALFORMED_JSON"));
        log.info("【坏JSON】非合法 JSON 返回 400 + code=MALFORMED_JSON，不静默丢弃");
    }

    @Test
    void missingField_hasDistinctReasonAndField() throws Exception {
        String body = "{\"idempotencyKey\":\"k9\",\"eventType\":\"login\",\"occurredAt\":\"" + nowIso() + "\"}";
        mvc.perform(post("/api/audit/events").contentType("application/json").content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rejected").value(1))
                .andExpect(jsonPath("$.results[0].reason").value("MISSING_REQUIRED_FIELD"))
                .andExpect(jsonPath("$.results[0].field").value("source"));
        log.info("【缺字段】拒绝 reason=MISSING_REQUIRED_FIELD field=source，原因可区分");
    }
}
