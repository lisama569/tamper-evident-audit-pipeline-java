package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.TamperException;
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
 * 本轮新增破坏类型的检测与“最早受影响序号”定位：
 * 改内容 / 删中间 / 删末尾整条 / 删末尾连续多条 / 相邻互换 / 半行截断；
 * 以及结论在重新打开（不依赖内存状态）后依然成立。
 */
class LedgerV2TamperDetectionTest {

    private static final Logger LOG = Logger.getLogger(LedgerV2TamperDetectionTest.class.getName());

    private @TempDir Path dir;

    private Path ledgerFile() {
        return dir.resolve("ledger.log");
    }

    private AppendOnlyLedger seed(int n) {
        AppendOnlyLedger l = new AppendOnlyLedger(ledgerFile());
        for (int i = 1; i <= n; i++) {
            l.append("key-" + i, "{\"v\":" + i + "}", 1000L + i);
        }
        assertEquals(-1L, l.verify());
        return l;
    }

    private List<String> lines() throws Exception {
        return Files.readAllLines(ledgerFile());
    }

    private void writeLines(List<String> ls) throws Exception {
        Files.write(ledgerFile(), (String.join("\n", ls) + "\n").getBytes(StandardCharsets.UTF_8));
    }

    private long reopenAndReportTamper(TestInfo info, String input, String basis) {
        TamperException ex = assertThrows(TamperException.class, () -> new AppendOnlyLedger(ledgerFile()));
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=" + input
                + " 判定依据=" + ex.getMessage() + " 最终状态=破坏，最早受影响=" + ex.getFirstTamperedSequence()
                + "（" + basis + "）");
        return ex.getFirstTamperedSequence();
    }

    @Test
    void modifiedContentDetected(TestInfo info) throws Exception {
        seed(4);
        List<String> ls = lines();
        String frame3 = ls.get(2);
        int idx = frame3.indexOf("\"body\":\"") + 8;
        char c = frame3.charAt(idx);
        char swapped = c == 'A' ? 'B' : 'A';
        ls.set(2, frame3.substring(0, idx) + swapped + frame3.substring(idx + 1));
        writeLines(ls);
        assertEquals(3L, reopenAndReportTamper(info, "篡改第3条密文", "被改的就是第3条"));
    }

    @Test
    void deletedMiddleRecordDetectedAtGap(TestInfo info) throws Exception {
        seed(5);
        List<String> ls = lines();
        List<String> kept = new java.util.ArrayList<>(ls);
        kept.remove(2); // 删除第3条（中间）
        writeLines(kept);
        assertEquals(3L, reopenAndReportTamper(info, "删除中间第3条", "第一个空缺序号=3"));
    }

    @Test
    void deletedLastRecordDetected(TestInfo info) throws Exception {
        seed(5);
        List<String> ls = lines();
        writeLines(ls.subList(0, 4)); // 删除末尾第5条
        assertEquals(5L, reopenAndReportTamper(info, "删除末尾第5条", "锚点对账：被删后第一个空缺=5"));
    }

    @Test
    void deletedLastSeveralRecordsDetectedAtFirstGap(TestInfo info) throws Exception {
        seed(6);
        List<String> ls = lines();
        writeLines(ls.subList(0, 3)); // 删除末尾第4、5、6条
        assertEquals(4L, reopenAndReportTamper(info, "删除末尾第4~6条", "被删后第一个空缺=4"));
    }

    @Test
    void adjacentSwapDetectedAtSmallerSequence(TestInfo info) throws Exception {
        seed(5);
        List<String> ls = new java.util.ArrayList<>(lines());
        java.util.Collections.swap(ls, 1, 2); // 相邻第2、3条互换
        writeLines(ls);
        assertEquals(2L, reopenAndReportTamper(info, "相邻第2、3条互换", "互换中较小的序号=2"));
    }

    @Test
    void halfLineTruncationDetectedAtMissingSequence(TestInfo info) throws Exception {
        seed(4);
        List<String> ls = lines();
        String last = ls.get(3);
        // 把最后一条完整记录从中间截断（保留其前半段、无换行结尾），模拟“只写了一半”
        byte[] prefix = String.join("\n", ls.get(0), ls.get(1), ls.get(2),
                last.substring(0, last.length() / 2)).getBytes(StandardCharsets.UTF_8);
        Files.write(ledgerFile(), prefix);
        assertEquals(4L, reopenAndReportTamper(info, "最后一条只写一半(半行截断)", "锚点声明应有第4条，截断后第一个空缺=4"));
    }

    @Test
    void tamperConclusionSurvivesReopenAndRejectsWritesAndPurges(TestInfo info) throws Exception {
        seed(3);
        List<String> ls = lines();
        writeLines(ls.subList(0, 2)); // 删末尾第3条
        long first1 = reopenAndReportTamper(info, "首次打开判定", "空缺=3");
        // 不依赖任何运行期内存：再开一次，结论一致
        long first2 = reopenAndReportTamper(info, "重新打开复判", "同一文件同一结论");
        assertEquals(first1, first2);

        AppendOnlyLedger degraded = AppendOnlyLedger.openDegraded(ledgerFile());
        assertTrue(degraded.isClosed());
        assertEquals(3L, degraded.firstTamperedSequence());
        TamperException w = assertThrows(TamperException.class,
                () -> degraded.append("kX", "{}", 99L));
        TamperException p = assertThrows(TamperException.class,
                () -> degraded.markPurged(1L));
        // 破坏后再核验必须仍报破坏（不能因只扫存活帧而洗白），且序号一致
        assertEquals(3L, degraded.verify());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 最终状态=破坏后追加与清除均被拒绝、重新核验仍报破坏: "
                + w.getMessage() + " / " + p.getMessage());
    }

    @Test
    void frameWithoutDekIsDetectedAsUnauthorizedDeletion(TestInfo info) throws Exception {
        seed(3);
        // 模拟“帧可见但 DEK 缺失”：无论成因（私删/旧版本崩溃窗口），打开都必须明确判破坏而非启动失败
        assertTrue(dir.resolve("keys").resolve("2.key").toFile().delete());
        TamperException ex = assertThrows(TamperException.class, () -> new AppendOnlyLedger(ledgerFile()));
        assertEquals(2L, ex.getFirstTamperedSequence());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=删除2.key但帧仍在"
                + " 判定依据=" + ex.getMessage() + " 最终状态=按未授权删除定位到2");
    }

    @Test
    void tamperStateObservableAndRetentionAlsoRejected(TestInfo info) throws Exception {
        seed(4);
        List<String> ls = lines();
        // 删除中间第 2 条
        List<String> kept = new java.util.ArrayList<>(ls);
        kept.remove(1);
        writeLines(kept);

        AppendOnlyLedger degraded = AppendOnlyLedger.openDegraded(ledgerFile());
        assertTrue(degraded.isClosed(), "状态查询必须能看到破坏状态");
        assertEquals(2L, degraded.firstTamperedSequence(), "最早受影响=空缺序号2");
        // 已解析的记录仍可只读查询（第2条被删，剩3条可见）
        assertEquals(3, degraded.count());

        com.github.lisama569.tamperevidentauditpipelinejava.retention.LegalHoldService holds =
                new com.github.lisama569.tamperevidentauditpipelinejava.retention.LegalHoldService(
                        dir.resolve("holds.log"));
        com.github.lisama569.tamperevidentauditpipelinejava.retention.RetentionService rs =
                new com.github.lisama569.tamperevidentauditpipelinejava.retention.RetentionService(
                        degraded, holds, 1, dir.resolve("keys"));
        TamperException ex = assertThrows(TamperException.class, rs::enforceNow);
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=删除中间第2条后执行到期清除"
                + " 判定依据=" + ex.getMessage() + " 最终状态=到期清除同样被明确拒绝，状态可查");
    }
}
