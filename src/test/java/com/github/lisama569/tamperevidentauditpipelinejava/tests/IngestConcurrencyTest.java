package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.lisama569.tamperevidentauditpipelinejava.config.PipelineProperties;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.HmacSigner;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.OutboxStore;
import com.github.lisama569.tamperevidentauditpipelinejava.ingest.IdempotencyIndex;
import com.github.lisama569.tamperevidentauditpipelinejava.ingest.IngestResult;
import com.github.lisama569.tamperevidentauditpipelinejava.ingest.IngestService;
import com.github.lisama569.tamperevidentauditpipelinejava.ingest.EventNormalizer;
import com.github.lisama569.tamperevidentauditpipelinejava.storage.FileAppendStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 并发接入：同一稳定幂等键被多线程同时提交，必须恰好一条 ACCEPTED，其余 DUPLICATE；
 * 不同键并发提交必须全部 ACCEPTED 且序号唯一无空洞。
 */
class IngestConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(IngestConcurrencyTest.class);

    private ObjectMapper mapper() {
        ObjectMapper m = new ObjectMapper();
        m.registerModule(new JavaTimeModule());
        m.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return m;
    }

    private record Harness(IngestService ingest, FileAppendStore store) {
    }

    private Harness harness(Path dir) throws Exception {
        ObjectMapper mapper = mapper();
        PipelineProperties props = new PipelineProperties();
        FileAppendStore store = new FileAppendStore(dir, new HmacSigner("s"), mapper);
        store.initialize();
        OutboxStore outbox = new OutboxStore(dir, mapper);
        outbox.initialize();
        IdempotencyIndex idx = new IdempotencyIndex(store);
        IngestService ingest = new IngestService(new EventNormalizer(props), store, idx, outbox);
        return new Harness(ingest, store);
    }

    private String eventJson(String key) throws Exception {
        return mapper().readTree("{\"idempotencyKey\":\"" + key + "\",\"source\":\"app\","
                + "\"eventType\":\"login\",\"occurredAt\":\"" + Instant.now() + "\","
                + "\"deviceId\":\"dev-001\"}").toString();
    }

    @Test
    void sameKeyConcurrentSubmissions_deduplicatedExactlyOnce(@TempDir Path dir) throws Exception {
        Harness h = harness(dir);
        int n = 32;
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(n);
        AtomicInteger accepted = new AtomicInteger();
        AtomicInteger duplicate = new AtomicInteger();
        List<Long> acceptedSeqs = java.util.Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < n; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    IngestResult r = h.ingest().submit(mapper().readTree(eventJson("same-key")), null);
                    if (r.outcome() == com.github.lisama569.tamperevidentauditpipelinejava.ingest.IngestOutcome.ACCEPTED) {
                        accepted.incrementAndGet();
                        acceptedSeqs.add(r.record().seq());
                    } else if (r.outcome() == com.github.lisama569.tamperevidentauditpipelinejava.ingest.IngestOutcome.DUPLICATE) {
                        duplicate.incrementAndGet();
                    }
                } catch (Exception e) {
                    log.error("submission error", e);
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(60, TimeUnit.SECONDS));
        pool.shutdown();

        assertEquals(1, accepted.get(), "同一幂等键必须恰好接受一次");
        assertEquals(n - 1, duplicate.get(), "其余全部判为重复");
        assertEquals(1, h.store().lastSeq(), "留存中只能有一条记录");
        assertEquals(1, acceptedSeqs.get(0));
        log.info("【同键并发】输入={} 次同键提交 判定依据=幂等键 same-key 最终状态: 1 ACCEPTED + {} DUPLICATE, 留存记录数={}",
                n, duplicate.get(), h.store().lastSeq());
    }

    @Test
    void distinctKeysConcurrent_allAcceptedUniqueGapless(@TempDir Path dir) throws Exception {
        Harness h = harness(dir);
        int n = 100;
        ExecutorService pool = Executors.newFixedThreadPool(20);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(n);
        List<IngestResult> results = java.util.Collections.synchronizedList(new ArrayList<>());
        for (int i = 0; i < n; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    results.add(h.ingest().submit(mapper().readTree(eventJson("key-" + idx)), null));
                } catch (Exception e) {
                    log.error("err", e);
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(60, TimeUnit.SECONDS));
        pool.shutdown();

        long accepted = results.stream().filter(
                r -> r.outcome() == com.github.lisama569.tamperevidentauditpipelinejava.ingest.IngestOutcome.ACCEPTED).count();
        assertEquals(n, accepted);
        assertEquals(n, h.store().lastSeq());
        long distinct = results.stream().map(r -> r.record().seq()).distinct().count();
        assertEquals(n, distinct, "序号必须唯一");
        log.info("【异键并发】输入={} 不同键 最终状态: 全部 ACCEPTED，序号 1..{} 唯一无空洞", n, n);
    }
}
