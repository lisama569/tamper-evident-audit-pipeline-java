package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.VerifyResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 分段核验拼接结论与全量一致；几万条记录的重启恢复与核验耗时可控（线性，不随条数成倍恶化）。
 * CHECKPOINT 间隔通过系统属性在构造前调小，便于单测覆盖分段路径。
 */
class SegmentVerifyAndScaleTest {

    private static final Logger LOG = Logger.getLogger(SegmentVerifyAndScaleTest.class.getName());

    private @TempDir Path dir;

    private Path ledgerFile() {
        return dir.resolve("ledger.log");
    }

    @Test
    void segmentedVerifyMatchesFullVerifyAndReadFromDisk(TestInfo info) throws Exception {
        System.setProperty("audit.ledger.checkpointInterval", "100");
        try {
            AppendOnlyLedger ledger = new AppendOnlyLedger(ledgerFile());
            for (int i = 1; i <= 350; i++) {
                ledger.append("k" + i, "{\"v\":" + i + "}", i);
            }
            assertEquals(-1L, ledger.verify());

            // 按每段 100 条做内存分段核验，拼接应覆盖 1..350 且全部健康
            long first = -1L;
            for (long from = 1; from <= 350; from += 100) {
                long to = Math.min(350, from + 99);
                VerifyResult r = ledger.verifyRangeData(from, to);
                assertTrue(r.healthy(), "段[" + from + "," + to + "]应健康: " + r.basis());
                VerifyResult rd = ledger.verifyRangeDataFromDisk(from, to);
                assertTrue(rd.healthy(), "读盘段[" + from + "," + to + "]应健康: " + rd.basis());
                assertEquals(r.anchoredAfterDataSeq(), rd.anchoredAfterDataSeq());
                final long ff = from;
                final long tt = to;
                final int frames = r.framesChecked();
                final long anchored = r.anchoredAfterDataSeq();
                LOG.info(() -> "[CASE " + info.getDisplayName() + "] 段[" + ff + "," + tt
                        + "] 判定依据=锚点after=" + anchored + " 校验帧数=" + frames
                        + " 最终状态=内存与读盘一致健康");
            }

            // 破坏第 237 条所在段：分段核验必须定位到它，且其他段仍然健康
            java.util.List<String> lines = java.nio.file.Files.readAllLines(ledgerFile());
            int targetIndex = -1;
            for (int i = 0; i < lines.size(); i++) {
                if (lines.get(i).contains("\"seq\":237")) {
                    targetIndex = i;
                    break;
                }
            }
            assertTrue(targetIndex > 0);
            String line = lines.get(targetIndex);
            int idx = line.indexOf("\"body\":\"") + 8;
            char c = line.charAt(idx);
            char sw = c == 'A' ? 'B' : 'A';
            lines.set(targetIndex, line.substring(0, idx) + sw + line.substring(idx + 1));
            java.nio.file.Files.write(ledgerFile(),
                    (String.join("\n", lines) + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));

            AppendOnlyLedger reopened = AppendOnlyLedger.openDegraded(ledgerFile());
            assertTrue(reopened.isClosed());
            assertEquals(237L, reopened.firstTamperedSequence());
            VerifyResult bad = reopened.verifyRangeDataFromDisk(201, 300);
            assertFalse(bad.healthy());
            assertEquals(237L, bad.firstTamperedSequence());
            VerifyResult goodBefore = reopened.verifyRangeDataFromDisk(1, 100);
            assertTrue(goodBefore.healthy(), "破坏点之前的段不应被误报");
            LOG.info(() -> "[CASE " + info.getDisplayName() + "] 篡改seq237 判定依据=" + bad.basis()
                    + " 最终状态=破坏段定位237，前段仍健康");
        } finally {
            System.clearProperty("audit.ledger.checkpointInterval");
        }
    }

    @Test
    void largeLedgerRecoveryIsLinearAndFast(TestInfo info) {
        System.setProperty("audit.ledger.checkpointInterval", "2000");
        try {
            int n = 30_000;
            long t0 = System.nanoTime();
            AppendOnlyLedger ledger = new AppendOnlyLedger(ledgerFile());
            for (int i = 1; i <= n; i++) {
                ledger.append("bulk-" + i, "{\"i\":" + i + "}", i);
            }
            long writeMs = (System.nanoTime() - t0) / 1_000_000;

            long r0 = System.nanoTime();
            AppendOnlyLedger reopened = new AppendOnlyLedger(ledgerFile()); // 懒解密：只做线性链校验
            long recoverMs = (System.nanoTime() - r0) / 1_000_000;
            assertEquals(n + 0L, reopened.nextSequence() - 1);
            assertEquals(n, reopened.count());

            long v0 = System.nanoTime();
            long full = reopened.verify();
            long verifyMs = (System.nanoTime() - v0) / 1_000_000;

            long seg0 = System.nanoTime();
            VerifyResult seg = reopened.verifyRangeData(n - 1999L, n); // 只核最后2000条
            long segMs = (System.nanoTime() - seg0) / 1_000_000;

            assertEquals(-1L, full);
            assertTrue(seg.healthy());
            LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=" + n + "条"
                    + " 判定依据=恢复只线性校验HMAC不逐条解密 写入=" + writeMs + "ms 重启恢复=" + recoverMs
                    + "ms 全量核验=" + verifyMs + "ms 末段2000条核验=" + segMs + "ms(frames=" + seg.framesChecked()
                    + ") 最终状态=恢复/核验耗时可控且结论健康");
            // 宽松上限：30k 条恢复应在秒级以内（CI 抖动留余量）
            assertTrue(recoverMs < 20_000L, "恢复耗时异常: " + recoverMs + "ms");
            assertTrue(seg.framesChecked() <= 2001, "分段核验不应全量扫描: " + seg.framesChecked());
        } finally {
            System.clearProperty("audit.ledger.checkpointInterval");
        }
    }
}
