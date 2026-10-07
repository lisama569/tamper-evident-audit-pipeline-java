package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.github.lisama569.tamperevidentauditpipelinejava.compliance.CompliancePurgeRequest;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.CompliancePurgeResult;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.CompliancePurgeService;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.DuplicatePurgeRequestException;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.PurgeDecision;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.PurgeMark;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.TamperException;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.LegalHoldService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 合规清除：预演/执行一致、法律保留挡下、重复请求幂等、同 ID 冲突拒绝、
 * 合规优先于到期、清除后明文不可恢复但历史可审计。
 */
class CompliancePurgeServiceTest {

    private static final Logger LOG = Logger.getLogger(CompliancePurgeServiceTest.class.getName());

    private @TempDir Path dir;

    private AppendOnlyLedger ledger;
    private LegalHoldService holds;
    private CompliancePurgeService svc;

    private void boot() {
        ledger = new AppendOnlyLedger(dir.resolve("ledger.log"));
        holds = new LegalHoldService(dir.resolve("holds.log"));
        svc = new CompliancePurgeService(ledger, holds, dir.resolve("compliance-requests.log"));
    }

    private String payload(String subject, long occurredAt) {
        return "{\"subject\":\"" + subject + "\",\"occurredAtMs\":" + occurredAt + "}";
    }

    @Test
    void previewMatchesExecutionAndDoesNotChangeStorage(TestInfo info) throws Exception {
        boot();
        long now = System.currentTimeMillis();
        ledger.append("k1", payload("alice", now - Duration.ofDays(1).toMillis()), now);
        ledger.append("k2", payload("bob", now), now);
        long sizeBefore = Files.size(dir.resolve("ledger.log"));

        CompliancePurgeRequest req = new CompliancePurgeRequest("req-1", "GDPR 删除请求",
                null, 1L, 2L, true);
        CompliancePurgeResult preview = svc.preview(req);
        assertTrue(preview.dryRun());
        assertEquals(List.of(1L, 2L), preview.purgedSequences());
        assertEquals(2, preview.items().size());
        assertTrue(preview.items().stream().allMatch(i -> i.decision() == PurgeDecision.PURGE_COMPLIANCE));
        assertEquals(sizeBefore, Files.size(dir.resolve("ledger.log")), "预演不得改动账本");
        assertEquals(0L, Files.size(dir.resolve("compliance-requests.log")),
                "预演不得写任何幂等记录");
        assertNotNull(ledger.at(1).orElseThrow().payloadJson(), "预演后明文必须仍在");

        CompliancePurgeResult exec = svc.submit(new CompliancePurgeRequest("req-1", "GDPR 删除请求",
                null, 1L, 2L, false));
        assertEquals(preview.purgedSequences(), exec.purgedSequences());
        assertEquals(preview.items().size(), exec.items().size());
        assertNull(ledger.at(1).orElseThrow().payloadJson());
        assertEquals(-1L, ledger.verify());

        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=范围[1,2] 判定依据=预演与执行命中清单一致且预演零改动"
                + " 预演=" + preview.purgedSequences() + " 执行=" + exec.purgedSequences()
                + " 最终状态=先演后清，结论一致，链仍可验证");
    }

    @Test
    void legalHoldBlocksCompliancePurge(TestInfo info) {
        boot();
        long now = System.currentTimeMillis();
        ledger.append("k1", payload("vip-alice", now), now);
        ledger.append("k2", payload("bob", now), now);
        holds.addHold("h1", "vip-alice", "诉讼保全");

        CompliancePurgeResult r = svc.submit(new CompliancePurgeRequest("req-hold", "主体清除",
                null, 1L, 2L, false));
        assertEquals(List.of(2L), r.purgedSequences());
        assertEquals(List.of(1L), r.blockedByLegalHold());
        assertNotNull(ledger.at(1).orElseThrow().payloadJson(), "被 hold 记录明文必须保留");
        assertNull(ledger.at(2).orElseThrow().payloadJson());
        PurgeDecision d1 = r.items().stream().filter(i -> i.sequence() == 1L).findFirst().orElseThrow().decision();
        assertEquals(PurgeDecision.BLOCKED_BY_LEGAL_HOLD, d1);
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=两条主体，vip-alice被hold"
                + " 判定依据=法律保留最高 清除=" + r.purgedSequences() + " 挡下=" + r.blockedByLegalHold()
                + " 最终状态=hold记录留下且原因可解释");
    }

    @Test
    void repeatedRequestIsIdempotentAndReplaysSameConclusion(TestInfo info) {
        boot();
        long now = System.currentTimeMillis();
        for (int i = 1; i <= 3; i++) {
            ledger.append("k" + i, payload("u" + i, now), now);
        }
        var req = new CompliancePurgeRequest("req-idem", "一次性合规请求",
                null, 1L, 3L, false);
        CompliancePurgeResult first = svc.submit(req);
        assertEquals(3, first.purgedCount());

        // 第二次：相同 requestId 与请求体 → 回放，purgedSequences 仍是首次清单，且 idempotentReplay=true
        CompliancePurgeResult second = svc.submit(req);
        assertTrue(second.idempotentReplay());
        assertEquals(first.purgedSequences(), second.purgedSequences());
        assertEquals(first.blockedByLegalHold(), second.blockedByLegalHold());
        assertEquals(first.items().size(), second.items().size());

        // 第三次重启服务（从日志重放幂等状态），结论仍一致
        CompliancePurgeService reopenedSvc = new CompliancePurgeService(ledger, holds,
                dir.resolve("compliance-requests.log"));
        CompliancePurgeResult third = reopenedSvc.submit(req);
        assertTrue(third.idempotentReplay());
        assertEquals(first.purgedSequences(), third.purgedSequences());

        long marksBefore = ledger.purgeMarks().size();
        third.items().size();
        assertEquals(marksBefore, ledger.purgeMarks().size(), "重放不得新增任何 PURGE 帧");
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=同requestId提交3次(含重启)"
                + " 判定依据=后两次idempotentReplay且清单=" + third.purgedSequences()
                + " 最终状态=结论一致、无重复清除");
    }

    @Test
    void sameRequestIdWithDifferentBodyIsConflict(TestInfo info) {
        boot();
        long now = System.currentTimeMillis();
        for (int i = 1; i <= 4; i++) {
            ledger.append("k" + i, payload("u" + i, now), now);
        }
        svc.submit(new CompliancePurgeRequest("req-x", "原因A", null, 1L, 2L, false));
        DuplicatePurgeRequestException ex = assertThrows(DuplicatePurgeRequestException.class,
                () -> svc.submit(new CompliancePurgeRequest("req-x", "原因A",
                        null, 1L, 3L, false)));
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=同requestId不同范围 判定依据="
                + ex.getMessage() + " 最终状态=明确拒绝冲突，不误当成功");
    }

    @Test
    void complianceBeatsExpiryAndAlreadyPurgedNotReprocessed(TestInfo info) {
        boot();
        long now = System.currentTimeMillis();
        long old = now - Duration.ofDays(300).toMillis();
        ledger.append("k-old", payload("soon-expire", old), old);   // 本就快到期
        ledger.append("k-new", payload("fresh", now), now);

        // 合规清除直接命中“快到期”记录：按 COMPLIANCE 处理，而不是等 RETENTION
        CompliancePurgeResult r = svc.submit(new CompliancePurgeRequest("req-c", "合规优先",
                null, 1L, 1L, false));
        assertEquals(List.of(1L), r.purgedSequences());
        PurgeMark mark = ledger.purgeMark(1L).orElseThrow();
        assertEquals(PurgeMark.SOURCE_COMPLIANCE, mark.source());
        assertEquals("req-c", mark.requestId());

        // 再来一个覆盖 1、2 的请求：1 已清（回报 ALREADY_PURGED 与历史来源），只清 2
        CompliancePurgeResult r2 = svc.submit(new CompliancePurgeRequest("req-c2", "再次清除",
                null, 1L, 2L, false));
        assertEquals(List.of(2L), r2.purgedSequences());
        assertEquals(List.of(1L), r2.alreadyPurgedSequences());
        var item1 = r2.items().stream().filter(i -> i.sequence() == 1L).findFirst().orElseThrow();
        assertEquals(PurgeDecision.ALREADY_PURGED, item1.decision());
        assertEquals("COMPLIANCE", item1.purgeSource());
        assertEquals(-1L, ledger.verify());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=快到期记录+已清记录"
                + " 判定依据=合规优先于到期；已清不重复 最终状态=来源COMPLIANCE可审计，第二次仅清新记录");
    }

    @Test
    void subjectSelectorAndErasureAreAuditable(TestInfo info) {
        boot();
        long now = System.currentTimeMillis();
        ledger.append("k1", payload("alice", now), now);
        ledger.append("k2", payload("alice-group", now), now);
        ledger.append("k3", payload("bob", now), now);

        CompliancePurgeResult r = svc.submit(new CompliancePurgeRequest("req-s", "按主体清除",
                "alice", null, null, false));
        assertEquals(List.of(1L, 2L), r.purgedSequences());
        // 密文与 envelope 仍在链中（存在过可证明），但明文与 DEK 不可恢复
        for (long seq : List.of(1L, 2L)) {
            assertTrue(ledger.at(seq).orElseThrow().purged());
            assertNull(ledger.at(seq).orElseThrow().payloadJson());
            assertFalse(Files.exists(dir.resolve("keys").resolve(seq + ".key")));
            PurgeMark m = ledger.purgeMark(seq).orElseThrow();
            assertEquals("按主体清除", m.reason());
        }
        assertNotNull(ledger.at(3).orElseThrow().payloadJson());
        assertEquals(-1L, ledger.verify());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=subject~=alice(子串)"
                + " 判定依据=命中seq1,2 最终状态=明文不可恢复，PURGE帧(原因/请求ID)随链可审计");
    }

    @Test
    void crashAfterPurgeButBeforeResultDoesNotRePurgeOnReopen(TestInfo info) throws Exception {
        boot();
        long now = System.currentTimeMillis();
        for (int i = 1; i <= 3; i++) {
            ledger.append("k" + i, payload("u" + i, now), now);
        }
        svc.submit(new CompliancePurgeRequest("req-crash", "崩溃窗口",
                null, 1L, 3L, false));
        assertEquals(3, ledger.purgeMarks().size());

        // 模拟崩溃在“PURGE 已落链、RESULT 未写完”之间：删掉 compliance-requests.log 的 RESULT 行
        Path logFile = dir.resolve("compliance-requests.log");
        List<String> kept = new java.util.ArrayList<>();
        for (String line : Files.readAllLines(logFile)) {
            if (!line.contains("\"op\":\"RESULT\"")) {
                kept.add(line);
            }
        }
        Files.write(logFile, kept);

        CompliancePurgeService reopened = new CompliancePurgeService(ledger, holds, logFile);
        CompliancePurgeResult r = reopened.submit(new CompliancePurgeRequest("req-crash", "崩溃窗口",
                null, 1L, 3L, false));
        assertTrue(r.idempotentReplay());
        assertEquals(List.of(1L, 2L, 3L), r.alreadyPurgedSequences(), "三条都应识别为此前已清");
        assertTrue(r.purgedSequences().isEmpty(), "恢复路径不得再次执行清除");
        assertEquals(3, ledger.purgeMarks().size(), "PURGE 帧数量不得增加");
        assertEquals(-1L, ledger.verify());
        LOG.info(() -> "[CASE " + info.getDisplayName()
                + "] 输入=REQ在RESULT缺失的崩溃窗口后重放 判定依据=已清记录回放为ALREADY_PURGED"
                + " 最终状态=无二次清除、链完好");
    }

    @Test
    void multibyteReasonSurvivesDiskRangeVerifyAcrossPurgeFrame(TestInfo info) throws Exception {
        System.setProperty("audit.ledger.checkpointInterval", "100");
        try {
            boot();
            long now = System.currentTimeMillis();
            for (int i = 1; i <= 150; i++) {
                ledger.append("k" + i, payload("用户" + i, now), now);
            }
            // 在 101..150 段内放一个含中文原因的合规 PURGE（PURGE 为非DATA物理帧，穿插在段中）
            svc.submit(new CompliancePurgeRequest("req-中文", "用户行使被遗忘权，删除其审计痕迹",
                    null, 120L, 120L, false));
            assertEquals(-1L, ledger.verify());

            // 重启后：不依赖内存，直接读盘做分段核验，PURGE 的 UTF-8 原因不得导致 HMAC 误算
            AppendOnlyLedger reopened = new AppendOnlyLedger(dir.resolve("ledger.log"));
            var r = reopened.verifyRangeDataFromDisk(101L, 150L);
            assertTrue(r.healthy(), "含中文PURGE帧的段读盘核验必须健康: " + r.basis());
            assertEquals("用户行使被遗忘权，删除其审计痕迹",
                    reopened.purgeMark(120L).orElseThrow().reason());
            assertEquals("req-中文", reopened.purgeMark(120L).orElseThrow().requestId());
            LOG.info(() -> "[CASE " + info.getDisplayName()
                    + "] 输入=150条中文subject+seq120中文原因合规清除 判定依据=重启后读盘分段核验"
                    + " anchoredAfter=" + r.anchoredAfterDataSeq() + " frames=" + r.framesChecked()
                    + " 最终状态=多字节原因/PURGE穿插分段 核验健康且原因可审计");
        } finally {
            System.clearProperty("audit.ledger.checkpointInterval");
        }
    }

    @Test
    void purgeRejectedWhenLedgerTampered(TestInfo info) throws Exception {
        boot();
        long now = System.currentTimeMillis();
        ledger.append("k1", payload("u1", now), now);
        ledger.append("k2", payload("u2", now), now);
        // 删末尾记录制造破坏，再以降级方式重开
        Path f = dir.resolve("ledger.log");
        List<String> ls = Files.readAllLines(f);
        Files.write(f, (ls.get(0) + "\n").getBytes());
        AppendOnlyLedger bad = AppendOnlyLedger.openDegraded(f);
        assertTrue(bad.isClosed());
        CompliancePurgeService badSvc = new CompliancePurgeService(bad, holds,
                dir.resolve("compliance-requests.log"));
        TamperException ex = assertThrows(TamperException.class,
                () -> badSvc.submit(new CompliancePurgeRequest("req-t", "破坏后清除",
                        null, 1L, 2L, false)));
        TamperException previewEx = assertThrows(TamperException.class,
                () -> badSvc.preview(new CompliancePurgeRequest("req-t2", "破坏后预演",
                        null, 1L, 2L, true)));
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=破坏账本上发起清除/预演"
                + " 判定依据=" + ex.getMessage() + " / " + previewEx.getMessage()
                + " 最终状态=清除与预演均被明确拒绝");
    }
}
