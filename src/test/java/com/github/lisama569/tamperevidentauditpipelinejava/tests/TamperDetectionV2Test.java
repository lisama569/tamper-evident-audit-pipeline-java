package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.TamperEvidence;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.TamperException;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.VerifyResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 本轮新增的破坏检测矩阵：内容篡改 / 删中间 / 删末尾整条 / 删末尾连续多条 /
 * 相邻互换 / 半条收尾；以及“结论重启后一致、不依赖内存”“破坏后拒绝写入与清除”。
 */
class TamperDetectionV2Test {

    private static final Logger LOG = Logger.getLogger(TamperDetectionV2Test.class.getName());

    private @TempDir Path dir;

    private Path ledgerFile() {
        return dir.resolve("ledger.log");
    }

    private AppendOnlyLedger ledgerWith(int n) {
        AppendOnlyLedger l = new AppendOnlyLedger(ledgerFile());
        for (int i = 1; i <= n; i++) {
            l.append("key-" + i, "{\"v\":" + i + "}", 1000L + i);
        }
        return l;
    }

    private List<String> lines() throws Exception {
        return Files.readAllLines(ledgerFile());
    }

    private void writeLines(List<String> lines) throws Exception {
        Files.write(ledgerFile(), lines);
    }

    @Test
    void contentAlterationDetectedAtEarliestSequence(TestInfo info) throws Exception {
        ledgerWith(4);
        List<String> ls = lines();
        int idx = ls.get(2).indexOf("\"body\":\"") + 8; // 第 3 条
        char c = ls.get(2).charAt(idx);
        ls.set(2, ls.get(2).substring(0, idx) + (c == 'A' ? 'B' : 'A') + ls.get(2).substring(idx + 1));
        writeLines(ls);
        AppendOnlyLedger bad = AppendOnlyLedger.openDegraded(ledgerFile());
        assertTrue(bad.isClosed());
        assertEquals(3L, bad.firstTamperedSequence());
        assertEquals(TamperEvidence.CONTENT_ALTERED, bad.evidence());
        assertThrows(TamperException.class, () -> bad.append("kX", "{}", 1L));
        assertThrows(TamperException.class, () -> bad.markPurged(1L));
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=改动第3条body 判定依据=" + bad.evidence()
                + " " + bad.tamperDetail() + " 最终状态=closed@3 且追加/清除均被拒绝");
    }

    @Test
    void middleRecordDeletionDetectedAtFirstGap(TestInfo info) throws Exception {
        ledgerWith(4);
        List<String> ls = lines();
        writeLines(List.of(ls.get(0), ls.get(2), ls.get(3))); // 删掉第 2 条
        AppendOnlyLedger bad = AppendOnlyLedger.openDegraded(ledgerFile());
        assertEquals(2L, bad.firstTamperedSequence());
        assertEquals(TamperEvidence.MIDDLE_FRAME_MISSING, bad.evidence());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=删除第2条 判定依据=" + bad.tamperDetail()
                + " 最终状态=最早受影响=2 MIDDLE_FRAME_MISSING");
    }

    @Test
    void tailSingleRecordDeletionDetected(TestInfo info) throws Exception {
        ledgerWith(5);
        List<String> ls = lines();
        writeLines(ls.subList(0, 4)); // 删掉末尾第 5 条
        AppendOnlyLedger bad = AppendOnlyLedger.openDegraded(ledgerFile());
        assertEquals(5L, bad.firstTamperedSequence());
        assertEquals(TamperEvidence.TAIL_RECORDS_MISSING, bad.evidence());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=删除末尾第5条 判定依据=" + bad.tamperDetail()
                + " 最终状态=指向删后第一个空缺位置 5");
    }

    @Test
    void tailConsecutiveRecordsDeletionDetectedAtFirstGap(TestInfo info) throws Exception {
        ledgerWith(6);
        List<String> ls = lines();
        writeLines(ls.subList(0, 3)); // 连续删掉 4,5,6
        AppendOnlyLedger bad = AppendOnlyLedger.openDegraded(ledgerFile());
        assertEquals(4L, bad.firstTamperedSequence());
        assertEquals(TamperEvidence.TAIL_RECORDS_MISSING, bad.evidence());
        assertTrue(bad.tamperDetail().contains("4"));
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=连续删除4,5,6 判定依据=" + bad.tamperDetail()
                + " 最终状态=第一个空缺位置=4（不是含糊结论）");
    }

    @Test
    void adjacentSwapDetectedAtSmallerSequence(TestInfo info) throws Exception {
        ledgerWith(4);
        List<String> ls = lines();
        // 交换第 2、3 行（DATA 帧 2 与 3）
        String a = ls.get(1);
        ls.set(1, ls.get(2));
        ls.set(2, a);
        writeLines(ls);
        AppendOnlyLedger bad = AppendOnlyLedger.openDegraded(ledgerFile());
        assertEquals(2L, bad.firstTamperedSequence());
        assertEquals(TamperEvidence.REORDERED, bad.evidence());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=相邻2/3互换 判定依据=" + bad.tamperDetail()
                + " 最终状态=REORDERED 定位到较小序号 2");
    }

    @Test
    void halfWrittenRealFrameTailDetected(TestInfo info) throws Exception {
        ledgerWith(3);
        List<String> ls = lines();
        // 用真实帧的 80% 内容模拟“最后一条只写了一半就中断”，且没有合法写入意图
        String real = ls.get(2);
        String half = real.substring(0, real.length() * 8 / 10);
        Files.write(ledgerFile(), (String.join("\n", ls.subList(0, 3)) + "\n" + half)
                .getBytes(StandardCharsets.UTF_8));
        AppendOnlyLedger bad = AppendOnlyLedger.openDegraded(ledgerFile());
        assertTrue(bad.isClosed());
        assertEquals(4L, bad.firstTamperedSequence());
        assertEquals(TamperEvidence.HALF_FRAME_TAIL, bad.evidence());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=第4条真帧只写80%且无意图 判定依据="
                + bad.tamperDetail() + " 最终状态=HALF_FRAME_TAIL@4");
    }

    @Test
    void garbageBytesWithoutFrameShapeAreTreatedAsTornWrite(TestInfo info) throws Exception {
        ledgerWith(2);
        Files.write(ledgerFile(), (Files.readString(ledgerFile()) + "GARBAGE_HALF_FR")
                .getBytes(StandardCharsets.UTF_8), java.nio.file.StandardOpenOption.WRITE);
        // 不含任何帧特征字段的杂散字节 = 崩溃撕裂，截断后健康
        AppendOnlyLedger l = new AppendOnlyLedger(ledgerFile());
        assertEquals(3L, l.nextSequence());
        assertEquals(-1L, l.verifyFull().firstTamperedSequence());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=尾部杂散字节GARBAGE_HALF_FR"
                + " 判定依据=无帧特征字段，按崩溃撕裂截断 最终状态=健康 next=3");
    }

    @Test
    void conclusionSurvivesRestartWithoutInMemoryState(TestInfo info) throws Exception {
        ledgerWith(5);
        writeLines(lines().subList(0, 4));
        // 第一次打开得到的结论
        AppendOnlyLedger first = AppendOnlyLedger.openDegraded(ledgerFile());
        long seq1 = first.firstTamperedSequence();
        TamperEvidence ev1 = first.evidence();
        // 关闭丢弃整个实例与内存，重新打开
        AppendOnlyLedger second = AppendOnlyLedger.openDegraded(ledgerFile());
        assertEquals(seq1, second.firstTamperedSequence());
        assertEquals(ev1, second.evidence());
        VerifyResult vr = second.verifyFull();
        assertFalse(vr.healthy());
        assertEquals(seq1, vr.firstTamperedSequence());
        assertEquals(ev1, vr.evidence());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=首次打开判破坏后重启"
                + " 判定依据=结论全部由磁盘+签名锚点重算 最终状态=两次结论一致 seq=" + seq1 + " ev=" + ev1);
    }

    @Test
    void healthyLedgerReopensAndKeepsAppending(TestInfo info) {
        AppendOnlyLedger l1 = ledgerWith(3);
        l1.append("key-4", "{\"v\":4}", 1004L);
        AppendOnlyLedger l2 = new AppendOnlyLedger(ledgerFile());
        assertFalse(l2.isClosed());
        assertEquals(5L, l2.nextSequence());
        VerifyResult r = l2.verifyFull();
        assertTrue(r.healthy());
        l2.append("key-5", "{\"v\":5}", 1005L);
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=健康账本重启"
                + " 判定依据=全链验签+锚点一致 最终状态=可继续追加到 seq=5");
    }
}
