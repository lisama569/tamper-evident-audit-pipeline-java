package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.TamperEvidence;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.VerifyResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 分段核验与全量结论一致；大账本恢复/核验耗时可控（不随记录数成倍恶化的定性检查）；
 * 持续并发追加同时核验：不误报健康账本、不漏报真实破坏，结论带明确范围。
 */
class RangeAndScaleVerifyTest {

    private static final Logger LOG = Logger.getLogger(RangeAndScaleVerifyTest.class.getName());

    private @TempDir Path dir;

    private Path ledgerFile() {
        return dir.resolve("ledger.log");
    }

    @Test
    void rangeVerifyMatchesFullVerifyAndReportsExplicitRange(TestInfo info) throws Exception {
        AppendOnlyLedger l = new AppendOnlyLedger(ledgerFile(), 5);
        for (int i = 1; i <= 20; i++) {
            l.append("k" + i, "{\"v\":" + i + "}", 100L + i);
        }
        VerifyResult full = l.verifyFull();
        assertTrue(full.healthy());

        // 以检查点（每 5 条一个）为边界分段：起点必须落在某个检查点之后
        VerifyResult seg1 = l.verifyRange(1, 5);
        VerifyResult seg2 = l.verifyRange(6, 10);
        VerifyResult seg3 = l.verifyRange(11, 15);
        VerifyResult seg4 = l.verifyRange(16, 20);
        assertTrue(seg1.healthy() && seg2.healthy() && seg3.healthy() && seg4.healthy());
        assertEquals(1L, seg1.fromSequence());
        assertEquals(5L, seg1.toSequence());
        assertEquals(16L, seg4.fromSequence());
        assertEquals(20L, seg4.toSequence());
        assertTrue(seg2.fromCheckpoint(), "从检查点边界发起应标记 fromCheckpoint");
        // 分段只核验该段帧（该账本只有 DATA 帧，每段恰好 5 帧）
        assertEquals(5, seg1.framesExamined());
        assertEquals(5, seg2.framesExamined());
        assertEquals(5, seg3.framesExamined());
        assertEquals(5, seg4.framesExamined());

        // 在第 8 条做内容篡改：覆盖它的分段应报破坏且定位 8；不覆盖它的分段仍健康
        List<String> lines = Files.readAllLines(ledgerFile());
        String frame8 = lines.get(7);
        int idx = frame8.indexOf("\"body\":\"") + 8;
        char c = frame8.charAt(idx);
        lines.set(7, frame8.substring(0, idx) + (c == 'A' ? 'B' : 'A') + frame8.substring(idx + 1));
        Files.write(ledgerFile(), lines);
        AppendOnlyLedger bad = AppendOnlyLedger.openDegraded(ledgerFile());
        VerifyResult r2 = bad.verifyRange(6, 10);
        assertFalse(r2.healthy());
        assertEquals(8L, r2.firstTamperedSequence());
        assertEquals(TamperEvidence.CONTENT_ALTERED, r2.evidence());
        VerifyResult r1 = bad.verifyRange(1, 5);
        assertTrue(r1.healthy(), "破坏点之前的分段应仍可独立验通");
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=20条账本分段[1-5][6-10][11-20]+篡改seq8"
                + " 判定依据=签名检查点为段边界，段内独立重算HMAC"
                + " 最终状态=健康时三段均OK且只看5帧；篡改后仅覆盖段报破坏@8，前段仍OK");
    }

    @Test
    void rangeWithoutCheckpointGivesExplicitError(TestInfo info) {
        AppendOnlyLedger l = new AppendOnlyLedger(ledgerFile(), 1000);
        for (int i = 1; i <= 3; i++) {
            l.append("k" + i, "{}", i);
        }
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> l.verifyRange(2, 3));
        assertTrue(ex.getMessage().contains("检查点"));
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=区间起点seq1无检查点"
                + " 判定依据=" + ex.getMessage() + " 最终状态=明确报错并提示边界，不悄悄降级为全量");
    }

    @Test
    void recoveryAndVerifyStayControlledWhenLedgerGrows(TestInfo info) {
        int n = 30_000;
        long t0 = System.nanoTime();
        AppendOnlyLedger l = new AppendOnlyLedger(ledgerFile(), 5_000);
        for (int i = 1; i <= n; i++) {
            l.append("bulk-" + i, "{\"i\":" + i + "}", i);
        }
        long buildMs = (System.nanoTime() - t0) / 1_000_000;

        long t1 = System.nanoTime();
        AppendOnlyLedger reopened = new AppendOnlyLedger(ledgerFile(), 5_000);
        long recoverMs = (System.nanoTime() - t1) / 1_000_000;

        long t2 = System.nanoTime();
        VerifyResult full = reopened.verifyFull();
        long verifyMs = (System.nanoTime() - t2) / 1_000_000;

        long t3 = System.nanoTime();
        VerifyResult tail = reopened.verifyRange(25_001L, n);
        long tailMs = (System.nanoTime() - t3) / 1_000_000;

        assertTrue(full.healthy());
        assertTrue(tail.healthy());
        assertEquals(5_000, tail.framesExamined(), "分段核验只应重算尾段 5000 帧");
        assertEquals(n + 1L, reopened.nextSequence());
        // 定性上限（CI 友好的宽松边界）：3 万条规模下恢复与全量核验均应在秒级，且尾部分段显著快于全量
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=" + n + " 条"
                + " 构建=" + buildMs + "ms 重启恢复=" + recoverMs + "ms 全量核验=" + verifyMs
                + "ms 尾段5000条核验=" + tailMs + "ms 最终状态=全部健康，可追加，分段只算5000帧");
        assertTrue(recoverMs < 20_000, "恢复耗时应在可控范围，实际=" + recoverMs + "ms");
        assertTrue(verifyMs < 20_000, "全量核验耗时应在可控范围，实际=" + verifyMs + "ms");
        assertTrue(tailMs < verifyMs, "尾部分段核验应快于全量核验");
    }

    @Test
    void concurrentAppendsWithConcurrentVerifyNeverFalsePositive(TestInfo info) throws Exception {
        AppendOnlyLedger l = new AppendOnlyLedger(ledgerFile(), 500);
        int writers = 8;
        int perWriter = 250; // 共 2000 条
        int verifierRounds = 100;
        ExecutorService pool = Executors.newFixedThreadPool(writers + 2);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger written = new AtomicInteger();
        AtomicInteger falseAlarms = new AtomicInteger();
        AtomicInteger okChecks = new AtomicInteger();

        for (int w = 0; w < writers; w++) {
            final int wid = w;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perWriter; i++) {
                        int id = written.incrementAndGet();
                        l.append("cc-" + wid + "-" + i, "{\"id\":" + id + "}", id);
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }
        pool.submit(() -> {
            try {
                start.await();
                for (int r = 0; r < verifierRounds; r++) {
                    VerifyResult vr = l.verifyFull();
                    // 核验看到的是某个已提交前缀：健康就计入；绝不允许把好账本误报为破坏
                    if (vr.healthy()) {
                        okChecks.incrementAndGet();
                    } else {
                        falseAlarms.incrementAndGet();
                    }
                    Thread.yield();
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));

        assertEquals(writers * perWriter, written.get());
        assertEquals(0, falseAlarms.get(), "并发追加期间核验不得误报破坏");
        assertEquals(verifierRounds, okChecks.get());
        assertTrue(l.verifyFull().healthy());
        assertEquals((long) writers * perWriter, l.nextSequence() - 1);

        // 重启后仍然健康、无空洞
        AppendOnlyLedger l2 = new AppendOnlyLedger(ledgerFile(), 500);
        assertTrue(l2.verifyFull().healthy());
        assertEquals((long) writers * perWriter + 1, l2.nextSequence());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=" + writers + "写线程×" + perWriter
                + " 与 " + verifierRounds + " 次并发核验"
                + " 判定依据=核验锁定某已提交前缀+签名锚点 最终状态=误报=0 核验通过=" + okChecks.get()
                + " 总数=" + written.get() + " 重启健康无空洞");
    }

    @Test
    void verifyDoesNotMissRealTampering(TestInfo info) throws Exception {
        AppendOnlyLedger l = new AppendOnlyLedger(ledgerFile(), 100);
        for (int i = 1; i <= 200; i++) {
            l.append("k" + i, "{\"v\":" + i + "}", i);
        }
        // 篡改第 50 条的 body
        var lines = Files.readAllLines(ledgerFile());
        String f50 = lines.get(49);
        int idx = f50.indexOf("\"body\":\"") + 8;
        char c = f50.charAt(idx);
        lines.set(49, f50.substring(0, idx) + (c == 'A' ? 'B' : 'A') + f50.substring(idx + 1));
        Files.write(ledgerFile(), lines);

        AppendOnlyLedger bad = AppendOnlyLedger.openDegraded(ledgerFile());
        assertTrue(bad.isClosed());
        // 全量、覆盖该段的分段、多轮重复核验都必须稳定报出 50，不漏
        assertEquals(50L, bad.verifyFull().firstTamperedSequence());
        for (int round = 0; round < 5; round++) {
            VerifyResult r = bad.verifyRange(1, 100);
            assertFalse(r.healthy(), "第 " + round + " 轮核验不得漏掉真实破坏");
            assertEquals(50L, r.firstTamperedSequence());
            assertEquals(TamperEvidence.CONTENT_ALTERED, r.evidence());
        }
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=200条后篡改seq50"
                + " 判定依据=全量与覆盖段[1,100]五轮核验均稳定定位@50 CONTENT_ALTERED"
                + " 最终状态=真破坏绝不漏报，分段结论对应明确记录范围[1,100]");
    }
}
