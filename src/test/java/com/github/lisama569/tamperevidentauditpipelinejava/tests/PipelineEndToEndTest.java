package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.tamperevidentauditpipelinejava.config.PipelineProperties;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.HttpForwarder;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.OutboxEntry;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.OutboxStore;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.RetryDispatcher;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.model.IngestResult;
import com.github.lisama569.tamperevidentauditpipelinejava.model.RejectReason;
import com.github.lisama569.tamperevidentauditpipelinejava.service.AuditPipelineService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 端到端：拒绝原因可区分、重启恢复、outbox 补登记、篡改后拒绝新追加、真实 HTTP 转发（含失败重投）。
 */
class PipelineEndToEndTest {

    private static final Logger LOG = Logger.getLogger(PipelineEndToEndTest.class.getName());
    private final ObjectMapper mapper = new ObjectMapper();

    private @TempDir Path dir;

    private PipelineProperties props(Path dir) {
        PipelineProperties p = new PipelineProperties();
        p.setStorageDir(dir);
        p.setAutoForward(false);
        p.setRetryInitialDelayMs(0L);
        p.setRetryMaxDelayMs(0L);
        return p;
    }

    @Test
    void rejectionReasonsAreDistinguishable(TestInfo info) throws Exception {
        AuditPipelineService svc = new AuditPipelineService(props(dir), mapper);
        // 非 JSON 对象（数组）→ MALFORMED_JSON
        IngestResult malformed = svc.ingest(mapper.readTree("[]"));
        assertFalse(malformed.accepted());
        assertEquals(RejectReason.MALFORMED_JSON, malformed.reason());
        check(svc, "{\"eventId\":\"e\"}", RejectReason.MISSING_REQUIRED_FIELD);
        check(svc, "{\"source\":9,\"eventId\":\"e\",\"eventType\":\"t\",\"occurredAt\":1}",
                RejectReason.FIELD_TYPE_MISMATCH);
        check(svc, "{\"source\":\"s\",\"eventId\":\"e\",\"eventType\":\"t\",\"occurredAt\":\"bad\"}",
                RejectReason.INVALID_TIMESTAMP);
        check(svc, "{\"source\":\"s\",\"eventId\":\"e\",\"eventType\":\"t\",\"occurredAt\":"
                        + (System.currentTimeMillis() + 999_999) + "}",
                RejectReason.SUSPICIOUS_TIMESTAMP);
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 最终状态=5 类非法输入全部按可区分原因拒绝，无静默丢弃");
        svc.close();
    }

    private void check(AuditPipelineService svc, String body, RejectReason reason) throws Exception {
        IngestResult r = svc.ingest(mapper.readTree(body));
        assertFalse(r.accepted());
        assertEquals(reason, r.reason());
    }

    @Test
    void restartPreservesLedgerAndDeduplicates(TestInfo info) throws Exception {
        PipelineProperties p = props(dir);
        AuditPipelineService s1 = new AuditPipelineService(p, mapper);
        s1.ingest(mapper.readTree(validBody("restart-1")));
        s1.ingest(mapper.readTree(validBody("restart-2")));
        s1.close();

        AuditPipelineService s2 = new AuditPipelineService(p, mapper);
        IngestResult dup = s2.ingest(mapper.readTree(validBody("restart-1")));
        IngestResult next = s2.ingest(mapper.readTree(validBody("restart-3")));
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定=重启后重复事件命中seq=" + dup.sequence()
                + " 新事件seq=" + next.sequence() + " 最终状态=幂等索引跨重启有效");
        assertTrue(dup.duplicate());
        assertEquals(1L, dup.sequence());
        assertEquals(3L, next.sequence());
        s2.close();
    }

    @Test
    void outboxRepairsMissingRegistrationAfterRestart(TestInfo info) throws Exception {
        PipelineProperties p = props(dir);
        AuditPipelineService s1 = new AuditPipelineService(p, mapper);
        s1.ingest(mapper.readTree(validBody("a")));
        s1.ingest(mapper.readTree(validBody("b")));
        s1.close();
        // 模拟“账本已追加、outbox 未持久化”的崩溃缝隙：删掉 outbox 日志
        Files.delete(p.getStorageDir().resolve("outbox.log"));

        AuditPipelineService s2 = new AuditPipelineService(p, mapper);
        List<OutboxEntry> all = s2.outbox().all();
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=outbox丢失但账本有2条"
                + " 判定依据=重开后outbox条目=" + all.size() + " 最终状态=转发不丢，补登记2条");
        assertEquals(2, all.size());
        assertEquals(1L, s2.outbox().resumePosition());
        s2.close();
    }

    @Test
    void newIngestsAreRejectedAfterTamper(TestInfo info) throws Exception {
        PipelineProperties p = props(dir);
        AuditPipelineService s1 = new AuditPipelineService(p, mapper);
        s1.ingest(mapper.readTree(validBody("x1")));
        s1.close();
        // 直接改账本密文
        Path ledger = p.getStorageDir().resolve("ledger.log");
        List<String> lines = Files.readAllLines(ledger);
        String fr = lines.get(0);
        int i = fr.indexOf("\"body\":\"") + 8;
        char c = fr.charAt(i);
        lines.set(0, fr.substring(0, i) + (c == 'A' ? 'B' : 'A') + fr.substring(i + 1));
        Files.write(ledger, lines);

        TamperOpenResult tor = openExpectingTamper(p);
        if (tor.service != null) {
            assertTrue(tor.service.ledger().isClosed());
            assertEquals(1L, tor.service.ledger().firstTamperedSequence());
            IngestResult r = tor.service.ingest(mapper.readTree(validBody("x2")));
            LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定=篡改后服务降级在线，新事件被拒绝 reason="
                    + r.reason() + " 最早受影响=" + tor.firstTampered);
            assertFalse(r.accepted());
            assertEquals(RejectReason.LEDGER_TAMPERED, r.reason());
            // 降级模式下清除同样必须被拒绝，而不是继续操作可疑账本
            assertThrows(com.github.lisama569.tamperevidentauditpipelinejava.ledger.TamperException.class,
                    tor.service::enforceRetention);
            tor.service.close();
        } else {
            LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定=账本在打开阶段即拒绝(最早受影响="
                    + tor.firstTampered + ") 最终状态=无可用写入，可疑内容不会继续落盘");
            assertEquals(1L, tor.firstTampered);
        }
    }

    private record TamperOpenResult(AuditPipelineService service, long firstTampered) {}

    private TamperOpenResult openExpectingTamper(PipelineProperties p) {
        try {
            AuditPipelineService s = new AuditPipelineService(p, mapper);
            return new TamperOpenResult(s, s.ledger().firstTamperedSequence());
        } catch (Exception e) {
            long seq = -1;
            Throwable c = e;
            while (c != null) {
                if (c instanceof com.github.lisama569.tamperevidentauditpipelinejava.ledger.TamperException te) {
                    seq = te.getFirstTamperedSequence();
                }
                c = c.getCause();
            }
            return new TamperOpenResult(null, seq);
        }
    }

    @Test
    void httpForwardSuccessThenNoDuplicate(TestInfo info) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        ConcurrentHashMap<String, AtomicInteger> received = new ConcurrentHashMap<>();
        server.createContext("/hook", (HttpExchange ex) -> {
            byte[] body = ex.getRequestBody().readAllBytes();
            String key = ex.getRequestHeaders().getFirst("Idempotency-Key");
            received.computeIfAbsent(key, k -> new AtomicInteger()).incrementAndGet();
            ex.sendResponseHeaders(200, -1);
            ex.close();
        });
        server.start();
        try {
            PipelineProperties p = props(dir);
            AuditPipelineService svc = new AuditPipelineService(p, mapper);
            svc.ingest(mapper.readTree(validBody("http-1")));
            RetryDispatcher d = new RetryDispatcher(svc.outbox(),
                    new HttpForwarder("http://localhost:" + server.getAddress().getPort() + "/hook",
                            HttpClient.newHttpClient(), 5000), 5, 0L, 0L, 60_000L, 60_000L);
            int processed = d.dispatchOnce();
            d.dispatchOnce();
            d.dispatchOnce();
            String key = svc.ledger().at(1).orElseThrow().idempotencyKey();
            LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=1事件+真实HTTP接收端"
                    + " 判定依据=处理数=" + processed + " 接收端收到次数="
                    + received.getOrDefault(key, new AtomicInteger()).get()
                    + " 最终状态=SENT且不重复转发");
            assertEquals(1, processed);
            assertEquals(1, received.get(key).get());
            assertEquals(OutboxEntry.SENT, svc.outbox().find(1L).orElseThrow().status());
            svc.close();
        } finally {
            server.stop(0);
        }
    }

    @Test
    void http500RetriedThenDelivered(TestInfo info) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        AtomicInteger calls = new AtomicInteger();
        server.createContext("/hook", (HttpExchange ex) -> {
            ex.getRequestBody().readAllBytes();
            int n = calls.incrementAndGet();
            ex.sendResponseHeaders(n < 3 ? 500 : 200, -1);
            ex.close();
        });
        server.start();
        try {
            PipelineProperties p = props(dir);
            AuditPipelineService svc = new AuditPipelineService(p, mapper);
            svc.ingest(mapper.readTree(validBody("http-retry")));
            RetryDispatcher d = new RetryDispatcher(svc.outbox(),
                    new HttpForwarder("http://localhost:" + server.getAddress().getPort() + "/hook",
                            HttpClient.newHttpClient(), 5000), 5, 0L, 0L, 60_000L, 60_000L);
            // 零退避，多轮派发：前两次500可重试，第三次成功
            for (int i = 0; i < 5; i++) {
                d.dispatchOnce();
            }
            LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定依据=接收端调用=" + calls.get()
                    + " 最终状态=" + svc.outbox().find(1L).orElseThrow().status());
            assertEquals(3, calls.get());
            assertEquals(OutboxEntry.SENT, svc.outbox().find(1L).orElseThrow().status());
            assertEquals(3, svc.outbox().find(1L).orElseThrow().attempts());
            svc.close();
        } finally {
            server.stop(0);
        }
    }

    @Test
    void http400IsNonRetryableDeadLetter(TestInfo info) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        AtomicInteger calls = new AtomicInteger();
        server.createContext("/hook", (HttpExchange ex) -> {
            ex.getRequestBody().readAllBytes();
            calls.incrementAndGet();
            ex.sendResponseHeaders(400, 4);
            ex.getResponseBody().write("bad!".getBytes(StandardCharsets.UTF_8));
            ex.close();
        });
        server.start();
        try {
            PipelineProperties p = props(dir);
            AuditPipelineService svc = new AuditPipelineService(p, mapper);
            OutboxStore store = svc.outbox();
            HttpForwarder fwd = new HttpForwarder("http://localhost:" + server.getAddress().getPort() + "/hook",
                    HttpClient.newHttpClient(), 5000);
            RetryDispatcher d = new RetryDispatcher(store, fwd, 5, 0L, 0L, 60_000L, 60_000L);
            svc.ingest(mapper.readTree(validBody("http-400")));
            d.dispatchOnce();
            d.dispatchOnce();
            LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定依据=400调用次数=" + calls.get()
                    + " 最终状态=" + store.find(1L).orElseThrow().status()
                    + " 类别=" + store.find(1L).orElseThrow().lastErrorCategory());
            assertEquals(1, calls.get());
            assertEquals(OutboxEntry.DEAD, store.find(1L).orElseThrow().status());
            assertEquals("HTTP_400", store.find(1L).orElseThrow().lastErrorCategory());
            svc.close();
        } finally {
            server.stop(0);
        }
    }

    private String validBody(String eventId) {
        return "{\"source\":\"web\",\"eventId\":\"" + eventId + "\",\"eventType\":\"click\","
                + "\"occurredAt\":\"2026-09-01T10:00:00Z\",\"device\":\"mobile\"}";
    }
}
