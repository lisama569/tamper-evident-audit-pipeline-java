package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.StoredEvent;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.VerifyResult;
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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 持续并发追加的同时做全量/分段核验：不得误报、核验对应明确范围；
 * 并发结束后全量核验必须健康，序号无空洞。
 */
class ConcurrentAppendVerifyTest {

    private static final Logger LOG = Logger.getLogger(ConcurrentAppendVerifyTest.class.getName());

    private @TempDir Path dir;

    @Test
    void concurrentAppendsWithConcurrentVerifyProduceNoFalsePositive(TestInfo info) throws Exception {
        System.setProperty("audit.ledger.checkpointInterval", "200");
        try {
            AppendOnlyLedger ledger = new AppendOnlyLedger(dir.resolve("ledger.log"));
            // 先打底 200 条，保证分段核验一开始就有锚点
            for (int i = 1; i <= 200; i++) {
                ledger.append("seed-" + i, "{\"i\":" + i + "}", i);
            }

            int writers = 8;
            int perWriter = 300; // 共 2400 条新追加
            ExecutorService pool = Executors.newFixedThreadPool(writers + 2);
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger writeErrors = new AtomicInteger();
            List<Long> assigned = Collections.synchronizedList(new ArrayList<>());
            AtomicBoolean verifyFalsePositive = new AtomicBoolean();
            List<String> verifyBasis = Collections.synchronizedList(new ArrayList<>());

            for (int t = 0; t < writers; t++) {
                final int base = t * perWriter;
                pool.submit(() -> {
                    try {
                        start.await();
                        for (int i = 0; i < perWriter; i++) {
                            long id = base + i + 200L;
                            StoredEvent e = ledger.append("evt-" + id, "{\"i\":" + id + "}", id);
                            assigned.add(e.sequence());
                        }
                    } catch (Exception ex) {
                        writeErrors.incrementAndGet();
                    }
                });
            }

            // 核验线程 1：反复全量核验。允许观察到“追加进行中”的稳定前缀，结论必须健康
            pool.submit(() -> {
                try {
                    start.await();
                    for (int round = 0; round < 50; round++) {
                        long first = ledger.verify();
                        if (first != -1L) {
                            verifyFalsePositive.set(true);
                            verifyBasis.add("全量核验误报 first=" + first);
                        }
                    }
                } catch (Exception ex) {
                    verifyFalsePositive.set(true);
                    verifyBasis.add("全量核验异常: " + ex);
                }
            });

            // 核验线程 2：反复对已稳定区间做分段核验（1..当前序号的前段），范围必须明确
            pool.submit(() -> {
                try {
                    start.await();
                    for (int round = 0; round < 50; round++) {
                        long head = Math.max(1L, ledger.nextSequence() - 250L);
                        long to = Math.min(ledger.nextSequence() - 1L, head + 199L);
                        if (to >= head) {
                            VerifyResult r = ledger.verifyRangeData(head, to);
                            if (!r.healthy()) {
                                verifyFalsePositive.set(true);
                                verifyBasis.add("分段[" + head + "," + to + "]误报: " + r.basis());
                            }
                        }
                    }
                } catch (Exception ex) {
                    verifyFalsePositive.set(true);
                    verifyBasis.add("分段核验异常: " + ex);
                }
            });

            start.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(90, TimeUnit.SECONDS));

            int total = writers * perWriter;
            Set<Long> unique = new HashSet<>(assigned);
            assertEquals(0, writeErrors.get(), "写入不应报错");
            assertEquals(total, assigned.size());
            assertEquals(total, unique.size(), "并发序号必须唯一");
            long maxSeq = assigned.stream().mapToLong(Long::longValue).max().orElseThrow();
            assertEquals(200L + total, maxSeq);
            assertEquals(-1L, ledger.verify(), "并发结束后全量核验必须健康无空洞");
            assertFalse(verifyFalsePositive.get(), "并发核验不得误报: " + verifyBasis);

            // 重开后结论一致、可继续追加
            AppendOnlyLedger reopened = new AppendOnlyLedger(dir.resolve("ledger.log"));
            assertEquals(-1L, reopened.verify());
            assertEquals(maxSeq + 1, reopened.append("final", "{}", maxSeq + 1).sequence());

            LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=" + writers + "写线程x" + perWriter
                    + "+2核验线程 判定依据=唯一序号=" + unique.size() + " 最大序号=" + maxSeq
                    + " 写入错误=0 核验误报=0 最终状态=并发追加与核验共存，结论自洽，重启一致");
        } finally {
            System.clearProperty("audit.ledger.checkpointInterval");
        }
    }
}
