package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.StoredEvent;
import com.github.lisama569.tamperevidentauditpipelinejava.model.IngestResult;
import com.github.lisama569.tamperevidentauditpipelinejava.service.AuditPipelineService;
import com.github.lisama569.tamperevidentauditpipelinejava.config.PipelineProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;
import java.util.stream.LongStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 并发追加：唯一性、无空洞、顺序一致性；并发重复提交按幂等键去重。
 */
class ConcurrentAppendTest {

    private static final Logger LOG = Logger.getLogger(ConcurrentAppendTest.class.getName());

    private @TempDir Path dir;

    @Test
    void concurrentAppendsProduceUniqueGaplessSequences(TestInfo info) throws Exception {
        AppendOnlyLedger ledger = new AppendOnlyLedger(dir.resolve("ledger.log"));
        int threads = 16;
        int perThread = 100;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Long> assigned = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger errors = new AtomicInteger();

        for (int t = 0; t < threads; t++) {
            final int base = t * perThread;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        long id = base + i;
                        StoredEvent e = ledger.append("key-" + id, "{\"id\":" + id + "}", id);
                        assigned.add(e.sequence());
                    }
                } catch (Exception ex) {
                    errors.incrementAndGet();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));

        int total = threads * perThread;
        List<Long> sorted = assigned.stream().sorted().toList();
        boolean gapless = sorted.equals(LongStream.rangeClosed(1, total).boxed().toList());
        boolean unique = new HashSet<>(sorted).size() == total;

        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=" + threads + "线程x" + perThread
                + " 判定依据=序号集合=1.." + total + " 唯一=" + unique + " 无空洞=" + gapless
                + " 错误数=" + errors.get()
                + " 最终状态=" + (unique && gapless && errors.get() == 0 ? "顺序一致" : "不一致"));

        assertEquals(0, errors.get());
        assertTrue(unique, "序号必须唯一");
        assertTrue(gapless, "序号必须无空洞");
        assertEquals(total, assigned.size());
        assertEquals(-1L, ledger.verify());

        // 重开后仍是同一组无空洞记录，且可继续追加
        AppendOnlyLedger reopened = new AppendOnlyLedger(dir.resolve("ledger.log"));
        assertEquals(total + 1L, reopened.append("key-final", "{}", total + 1L).sequence());
        assertEquals(-1L, reopened.verify());
    }

    @Test
    void concurrentDuplicateSubmissionsDeduplicatedByIdempotencyKey(TestInfo info) throws Exception {
        PipelineProperties props = new PipelineProperties();
        props.setStorageDir(dir);
        props.setAutoForward(false);
        AuditPipelineService svc = new AuditPipelineService(props, new ObjectMapper());

        int submissions = 200; // 全部提交同一个业务事件
        ExecutorService pool = Executors.newFixedThreadPool(20);
        CountDownLatch start = new CountDownLatch(1);
        List<IngestResult> results = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger rejected = new AtomicInteger();
        String body = "{\"source\":\"web\",\"eventId\":\"dup-1\",\"eventType\":\"click\","
                + "\"occurredAt\":\"2026-09-01T10:00:00Z\"}";

        for (int i = 0; i < submissions; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    IngestResult r = svc.ingest(new ObjectMapper().readTree(body));
                    results.add(r);
                    if (!r.accepted()) {
                        rejected.incrementAndGet();
                    }
                } catch (Exception e) {
                    rejected.incrementAndGet();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));

        long news = results.stream().filter(r -> r.accepted() && !r.duplicate()).count();
        long dups = results.stream().filter(IngestResult::duplicate).count();
        Set<Long> seqs = new HashSet<>(results.stream().map(IngestResult::sequence).toList());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=" + submissions + "个并发相同事件"
                + " 判定依据=新写入=" + news + " 幂等重复=" + dups + " 拒绝=" + rejected.get()
                + " 不同序号=" + seqs + " 最终状态=恰好1条落库，其余幂等命中同一序号");
        assertEquals(1, news);
        assertEquals(submissions - 1, dups);
        assertEquals(0, rejected.get());
        assertEquals(1, seqs.size());
        assertEquals(1L, svc.ledger().nextSequence() - 1);
        svc.close();
    }

    @Test
    void concurrentDistinctEventsAllAcceptedInOrder(TestInfo info) throws Exception {
        PipelineProperties props = new PipelineProperties();
        props.setStorageDir(dir);
        props.setAutoForward(false);
        AuditPipelineService svc = new AuditPipelineService(props, new ObjectMapper());

        int n = 300;
        ExecutorService pool = Executors.newFixedThreadPool(24);
        CountDownLatch start = new CountDownLatch(1);
        List<IngestResult> results = Collections.synchronizedList(new ArrayList<>());
        for (int i = 0; i < n; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    String body = "{\"source\":\"s" + (idx % 4) + "\",\"eventId\":\"e" + idx
                            + "\",\"eventType\":\"t\",\"occurredAt\":\"2026-09-01T10:00:00Z\"}";
                    results.add(svc.ingest(new ObjectMapper().readTree(body)));
                } catch (Exception ignored) {
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));

        Set<Long> seqs = new HashSet<>(results.stream().map(IngestResult::sequence).toList());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=" + n + "个并发不同事件"
                + " 判定依据=接受=" + results.size() + " 不同序号=" + seqs.size()
                + " 最终状态=全部唯一落库");
        assertEquals(n, results.size());
        assertEquals(n, seqs.size());
        assertTrue(results.stream().allMatch(IngestResult::accepted));
        assertEquals(-1L, svc.ledger().verify());
        svc.close();
    }
}
