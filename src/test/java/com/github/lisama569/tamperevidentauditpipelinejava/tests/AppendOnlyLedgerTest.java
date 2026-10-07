package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.StoredEvent;
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
 * 只追加账本：顺序/无空洞、崩溃半帧截断、重启可验证、篡改定位与关闭、加密擦除清除。
 */
class AppendOnlyLedgerTest {

    private static final Logger LOG = Logger.getLogger(AppendOnlyLedgerTest.class.getName());

    private @TempDir Path dir;

    private Path ledgerFile() {
        return dir.resolve("ledger.log");
    }

    @Test
    void appendAssignsGaplessSequenceAndRoundTrips(TestInfo info) {
        AppendOnlyLedger ledger = new AppendOnlyLedger(ledgerFile());
        for (int i = 1; i <= 5; i++) {
            StoredEvent e = ledger.append("key-" + i, "{\"v\":" + i + "}", 1000L + i);
            assertEquals(i, e.sequence());
        }
        assertEquals(-1L, ledger.verify());
        assertEquals("{\"v\":3}", ledger.at(3).orElseThrow().payloadJson());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=5 条追加 判定依据=序号1..5且verify=-1"
                + " 最终状态=一致且可往返(解密得到原文)");
    }

    @Test
    void reopenReplaysAndKeepsChain(TestInfo info) throws Exception {
        AppendOnlyLedger l1 = new AppendOnlyLedger(ledgerFile());
        l1.append("k1", "p1", 11L);
        l1.append("k2", "p2", 12L);
        AppendOnlyLedger l2 = new AppendOnlyLedger(ledgerFile());
        StoredEvent e2 = l2.at(2).orElseThrow();
        assertEquals("p2", e2.payloadJson());
        assertEquals(3L, l2.nextSequence());
        StoredEvent e3 = l2.append("k3", "p3", 13L);
        assertEquals(3L, e3.sequence());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定依据=重开后nextSequence=3且可继续追加"
                + " 最终状态=哈希链跨重启连续");
    }

    @Test
    void tornTailFrameIsTruncatedNotVisible(TestInfo info) throws Exception {
        AppendOnlyLedger l1 = new AppendOnlyLedger(ledgerFile());
        l1.append("k1", "p1", 1L);
        l1.append("k2", "p2", 2L);
        // 模拟崩溃：在文件尾部追加无法解析的半行字节
        Files.write(ledgerFile(), "GARBAGE_HALF_FR".getBytes(StandardCharsets.UTF_8),
                java.nio.file.StandardOpenOption.APPEND);
        AppendOnlyLedger l2 = new AppendOnlyLedger(ledgerFile());
        assertEquals(3L, l2.nextSequence());
        List<String> lines = Files.readAllLines(ledgerFile());
        assertEquals(2, lines.size());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=尾部半帧 判定依据=打开后半帧被截断"
                + " 最终状态=无半条记录可见 nextSequence=2");
    }

    @Test
    void tamperedPayloadIsDetectedAtEarliestRecordAndLedgerCloses(TestInfo info) throws Exception {
        AppendOnlyLedger l1 = new AppendOnlyLedger(ledgerFile());
        l1.append("k1", "p1", 1L);
        l1.append("k2", "p2", 2L);
        l1.append("k3", "p3", 3L);
        // 篡改第 2 条帧的 body（密文被改）
        Path f = ledgerFile();
        List<String> lines = Files.readAllLines(f);
        String frame2 = lines.get(1);
        int idx = frame2.indexOf("\"body\":\"");
        char c = frame2.charAt(idx + 8);
        char swapped = c == 'A' ? 'B' : 'A';
        lines.set(1, frame2.substring(0, idx + 8) + swapped + frame2.substring(idx + 9));
        Files.write(f, lines);

        TamperException ex = assertThrows(TamperException.class, () -> new AppendOnlyLedger(f));
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=篡改第2条 判定依据=" + ex.getMessage()
                + " 最终状态=定位最早受影响序号并拒绝打开追加");
        assertEquals(2L, ex.getFirstTamperedSequence());

        // 即便强行拿到实例，closed 状态下追加也必须被拒绝
        AppendOnlyLedger reopened = openQuietly(f);
        if (reopened != null) {
            assertThrows(TamperException.class, () -> reopened.append("kX", "pX", 9L));
        }
    }

    @Test
    void deletedRecordIsDetected(TestInfo info) throws Exception {
        AppendOnlyLedger l1 = new AppendOnlyLedger(ledgerFile());
        l1.append("k1", "p1", 1L);
        l1.append("k2", "p2", 2L);
        Path f = ledgerFile();
        List<String> lines = Files.readAllLines(f);
        // 删除第 1 条：链断裂且第一个数据序号空缺为 1（“最早受影响/第一个空缺位置”语义）
        Files.write(f, List.of(lines.get(1)));
        TamperException ex = assertThrows(TamperException.class, () -> new AppendOnlyLedger(f));
        assertEquals(1L, ex.getFirstTamperedSequence());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=删除第1条 判定依据=" + ex.getMessage()
                + " 最终状态=删除可检测，最早受影响/第一个空缺序号=1");
    }

    @Test
    void unauthorizedKeyDeletionIsDetected(TestInfo info) {
        AppendOnlyLedger l1 = new AppendOnlyLedger(ledgerFile());
        l1.append("k1", "p1", 1L);
        l1.append("k2", "p2", 2L);
        // 未经 PURGE 流程直接删除 DEK
        assertTrue(dir.resolve("keys").resolve("1.key").toFile().delete());
        TamperException ex = assertThrows(TamperException.class, () -> new AppendOnlyLedger(ledgerFile()));
        assertEquals(1L, ex.getFirstTamperedSequence());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=私删1.key 判定依据=" + ex.getMessage()
                + " 最终状态=未授权删除被检测");
    }

    @Test
    void purgeCryptoErasesPayloadButChainVerifies(TestInfo info) {
        AppendOnlyLedger ledger = new AppendOnlyLedger(ledgerFile());
        ledger.append("k1", "p1-secret", 1L);
        ledger.markPurged(1L);
        assertNull(ledger.at(1).orElseThrow().payloadJson());
        assertTrue(ledger.at(1).orElseThrow().purged());
        assertEquals(-1L, ledger.verify());
        assertFalse(Files.exists(dir.resolve("keys").resolve("1.key")));
        // 重开后仍是已清除状态，链仍可验证
        AppendOnlyLedger l2 = new AppendOnlyLedger(ledgerFile());
        assertTrue(l2.at(1).orElseThrow().purged());
        assertEquals(-1L, l2.verify());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=清除seq1 判定依据=DEK已删/载荷null/verify=-1"
                + " 最终状态=加密擦除成功且链可验证");
    }

    @Test
    void appendsAfterTamperAreRejected(TestInfo info) throws Exception {
        AppendOnlyLedger l1 = new AppendOnlyLedger(ledgerFile());
        l1.append("k1", "p1", 1L);
        Path f = ledgerFile();
        List<String> lines = Files.readAllLines(f);
        String fr = lines.get(0);
        int i = fr.indexOf("\"stored\":");
        lines.set(0, fr.substring(0, i + 9) + "9" + fr.substring(i + 10));
        Files.write(f, lines);
        AppendOnlyLedger bad = openQuietly(f);
        // 构造方式可能直接抛出；若返回实例则其必须已关闭
        if (bad != null) {
            assertTrue(bad.isClosed());
            assertThrows(TamperException.class, () -> bad.append("k2", "p2", 2L));
        }
        LOG.info(() -> "[CASE " + info.getDisplayName()
                + "] 输入=篡改stored字段 判定依据=HMAC校验失败→closed 最终状态=新追加被明确拒绝");
    }

    private AppendOnlyLedger openQuietly(Path f) {
        try {
            return new AppendOnlyLedger(f);
        } catch (TamperException e) {
            return null;
        }
    }
}
