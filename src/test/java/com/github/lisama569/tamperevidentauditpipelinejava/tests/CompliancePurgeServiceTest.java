package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.github.lisama569.tamperevidentauditpipelinejava.compliance.CompliancePurgeRequest;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.CompliancePurgeResult;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.CompliancePurgeService;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.DuplicatePurgeRequestException;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.RecordDecision;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.TamperException;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.LegalHoldService;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.PurgeSource;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.RetentionService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Map;
import java.util.stream.Collectors;
import java.time.Duration;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 主动合规清除：预演/执行一致、法律保留挡下、幂等（含重启）、优先级可解释、
 * 合规高于到期、已清除不重复处理、清除来源可审计。
 */
class CompliancePurgeServiceTest {

    private static final Logger LOG = Logger.getLogger(CompliancePurgeServiceTest.class.getName());

    private @TempDir Path dir;

    private AppendOnlyLedger newLedger() {
        return new AppendOnlyLedger(dir.resolve("ledger.log"));
    }

    private CompliancePurgeService newCompliance(AppendOnlyLedger l, LegalHoldService h) {
        return new CompliancePurgeService(l, h, dir);
    }

    private LegalHoldService newHolds() {
        return new LegalHoldService(dir.resolve("holds.log"));
    }

    private String payload(String subject, long occurredAtMs) {
        return "{\"subject\":\"" + subject + "\",\"occurredAtMs\":" + occurredAtMs + "}";
    }

    private Map<Long, RecordDecision> decisions(CompliancePurgeResult r) {
        return r.items().stream().collect(Collectors.toMap(
                com.github.lisama569.tamperevidentauditpipelinejava.compliance.RecordPurgeItem::sequence,
                com.github.lisama569.tamperevidentauditpipelinejava.compliance.RecordPurgeItem::decision));
    }

    @Test
    void previewDoesNotChangeRetentionAndMatchesExecution(TestInfo info) {
        AppendOnlyLedger l = newLedger();
        long now = System.currentTimeMillis();
        l.append("k1", payload("alice", now), now);
        l.append("k2", payload("alice", now), now);
        LegalHoldService h = newHolds();
        CompliancePurgeService cps = newCompliance(l, h);

        CompliancePurgeRequest req = new CompliancePurgeRequest(
                "req-1", "GDPR deletion request", "alice", null, null, false);
        CompliancePurgeResult preview = cps.preview(req);

        // 预演不改任何留存
        assertNotNull(l.at(1).orElseThrow().payloadJson());
        assertNotNull(l.at(2).orElseThrow().payloadJson());
        assertTrue(preview.dryRun());
        assertEquals(java.util.List.of(1L, 2L), preview.purgedSequences());
        assertTrue(preview.blockedByLegalHold().isEmpty());
        assertTrue(decisions(preview).values().stream().allMatch(d -> d == RecordDecision.WILL_PURGE));
        assertEquals(-1L, l.verifyFull().firstTamperedSequence());

        CompliancePurgeResult exec = cps.execute(req);
        // 预演结论与执行结论一致（命中集合）；执行后明文真的没了
        assertEquals(preview.purgedSequences(), exec.purgedSequences());
        assertEquals(preview.blockedByLegalHold(), exec.blockedByLegalHold());
        assertNull(l.at(1).orElseThrow().payloadJson());
        assertNull(l.at(2).orElseThrow().payloadJson());
        assertEquals(PurgeSource.COMPLIANCE, l.at(1).orElseThrow().purgeSource());
        assertEquals("req-1", l.at(1).orElseThrow().purgeRequestId());
        assertEquals("GDPR deletion request", l.at(1).orElseThrow().purgeReason());
        assertEquals(-1L, l.verifyFull().firstTamperedSequence());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=按主体预演再执行"
                + " 判定依据=预演集合=" + preview.purgedSequences() + " == 执行集合=" + exec.purgedSequences()
                + " 最终状态=预演零改动；执行后加密擦除、PURGE 帧带 requestId/reason、链仍可验");
    }

    @Test
    void legalHoldBlocksCompliancePurge(TestInfo info) {
        AppendOnlyLedger l = newLedger();
        long now = System.currentTimeMillis();
        l.append("k1", payload("vip-alice", now), now);
        l.append("k2", payload("bob", now), now);
        LegalHoldService h = newHolds();
        h.addHold("hold-1", "vip", "litigation freeze");
        CompliancePurgeService cps = newCompliance(l, h);

        CompliancePurgeRequest req = new CompliancePurgeRequest("req-hold", "subject-wide",
                null, 1L, 2L, false);
        CompliancePurgeResult preview = cps.preview(req);
        CompliancePurgeResult exec = cps.execute(req);

        assertEquals(java.util.List.of(2L), exec.purgedSequences());
        assertEquals(java.util.List.of(1L), exec.blockedByLegalHold());
        assertEquals(RecordDecision.BLOCKED_BY_LEGAL_HOLD, decisions(exec).get(1L));
        assertNotNull(l.at(1).orElseThrow().payloadJson(), "被法律保留挡下的记录不得清除");
        assertNull(l.at(2).orElseThrow().payloadJson());
        assertEquals(java.util.List.of(1L), exec.retainedSequences());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=范围[1,2] 且seq1命中hold"
                + " 判定依据=法律保留最高 最终状态=seq1挡下且明文保留, seq2合规清除; 预演="
                + preview.blockedByLegalHold());
    }

    @Test
    void repeatedRequestIsIdempotentIncludingRestart(TestInfo info) {
        AppendOnlyLedger l = newLedger();
        long now = System.currentTimeMillis();
        for (int i = 1; i <= 3; i++) {
            l.append("k" + i, payload("alice", now), now);
        }
        LegalHoldService h = newHolds();
        CompliancePurgeService cps1 = newCompliance(l, h);
        CompliancePurgeRequest req = new CompliancePurgeRequest("req-idem", "r",
                "alice", null, null, false);
        CompliancePurgeResult first = cps1.execute(req);

        // 同进程第二次：结论一致、不重复处理
        CompliancePurgeResult second = cps1.execute(req);
        assertEquals(first.purgedSequences(), second.purgedSequences());
        assertEquals(first.items().size(), second.items().size());
        // 首次之后新增一条同主体记录：重放不得多清（评估边界已固定）
        l.append("k4", payload("alice", now), now);
        CompliancePurgeResult third = newCompliance(newLedger(), h).execute(req); // 新实例但同一目录(重启)
        assertEquals(first.purgedSequences(), third.purgedSequences());
        assertNotNull(l.at(4).orElseThrow().payloadJson(), "请求之后新增的记录不应被同请求重放清除");
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=同requestId三次(含重启)+新增同主体记录"
                + " 判定依据=结论持久化+evalUpTo边界固定 最终状态=三次集合一致=" + first.purgedSequences()
                + " 且 seq4 保留");
    }

    @Test
    void conflictingSameRequestIdWithDifferentSelectorRejected(TestInfo info) {
        AppendOnlyLedger l = newLedger();
        long now = System.currentTimeMillis();
        l.append("k1", payload("alice", now), now);
        l.append("k2", payload("bob", now), now);
        CompliancePurgeService cps = newCompliance(l, newHolds());
        cps.execute(new CompliancePurgeRequest("rc", "reason", "alice", null, null, false));
        DuplicatePurgeRequestException ex = assertThrows(DuplicatePurgeRequestException.class,
                () -> cps.execute(new CompliancePurgeRequest("rc", "reason", "bob", null, null, false)));
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=同id不同subject"
                + " 判定依据=" + ex.getMessage() + " 最终状态=409 幂等冲突，拒绝按新参数执行");
    }

    @Test
    void compliancePurgeBeatsExpiryForExpiringRecord(TestInfo info) {
        AppendOnlyLedger l = newLedger();
        LegalHoldService h = newHolds();
        RetentionService retention = new RetentionService(l, h, 90, dir.resolve("keys"));
        long cutoff = Long.parseLong(retention.enforceNow().policy().replaceAll(".*cutoffMs=", "")
                .replaceAll("\\D.*", ""));
        long minute = Duration.ofMinutes(1).toMillis();
        // 一条马上要到期（cutoff-1min）、一条远未到期
        l.append("old", payload("zoe", cutoff - minute), cutoff - minute);
        l.append("new", payload("zoe", cutoff + Duration.ofDays(30).toMillis()),
                cutoff + Duration.ofDays(30).toMillis());

        CompliancePurgeService cps = newCompliance(l, h);
        CompliancePurgeResult r = cps.execute(new CompliancePurgeRequest("rp", "legal matter",
                "zoe", null, null, false));
        assertEquals(java.util.List.of(1L, 2L), r.purgedSequences());
        // 两条都按 COMPLIANCE 来源，而不是老记录 EXPIRY
        assertEquals(PurgeSource.COMPLIANCE, l.at(1).orElseThrow().purgeSource());
        assertEquals(PurgeSource.COMPLIANCE, l.at(2).orElseThrow().purgeSource());
        // 再跑到期策略，已清记录不重复处理
        var expiry = retention.enforceNow();
        assertTrue(expiry.purgedSequences().isEmpty());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=快到期+未到期各一，命中合规清除"
                + " 判定依据=合规清除>保留到期 最终状态=两条均COMPLIANCE清除，到期策略不再重复处理");
    }

    @Test
    void alreadyPurgedRecordsAreNotReProcessedAndSourceDistinguished(TestInfo info) {
        AppendOnlyLedger l = newLedger();
        LegalHoldService h = newHolds();
        RetentionService retention = new RetentionService(l, h, 90, dir.resolve("keys"));
        long cutoff = Long.parseLong(retention.enforceNow().policy().replaceAll(".*cutoffMs=", "")
                .replaceAll("\\D.*", ""));
        l.append("old-1", payload("alice", cutoff - Duration.ofMinutes(2).toMillis()),
                cutoff - Duration.ofMinutes(2).toMillis());
        l.append("new-2", payload("alice", cutoff + Duration.ofDays(10).toMillis()),
                cutoff + Duration.ofDays(10).toMillis());
        // seq1 先被到期清除
        var expiry = retention.enforceNow();
        assertEquals(java.util.List.of(1L), expiry.purgedSequences());

        CompliancePurgeService cps = newCompliance(l, h);
        // 用范围选择器（已加密擦除的 seq1 明文不可回溯 subject，序号范围仍能覆盖并给出可解释结论）
        CompliancePurgeResult r = cps.execute(new CompliancePurgeRequest("ra", "r",
                null, 1L, 2L, false));
        var d = decisions(r);
        assertEquals(RecordDecision.ALREADY_PURGED_EXPIRY, d.get(1L));
        assertEquals(RecordDecision.PURGED, d.get(2L));
        assertEquals(java.util.List.of(1L), r.alreadyPurged());
        assertEquals(java.util.List.of(2L), r.purgedSequences());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=seq1已到期清, seq2未到期, 合规按范围[1,2]清"
                + " 判定依据=已清不重复(ALREADY_PURGED_EXPIRY) + 合规>到期 最终状态=seq1不动, seq2按COMPLIANCE清");
    }

    @Test
    void purgeRefusedWhenLedgerClosed(TestInfo info) throws Exception {
        AppendOnlyLedger l = newLedger();
        l.append("k1", payload("alice", 1L), 1L);
        var lines = java.nio.file.Files.readAllLines(dir.resolve("ledger.log"));
        int idx = lines.get(0).indexOf("\"body\":\"") + 8;
        char c = lines.get(0).charAt(idx);
        lines.set(0, lines.get(0).substring(0, idx) + (c == 'A' ? 'B' : 'A') + lines.get(0).substring(idx + 1));
        java.nio.file.Files.write(dir.resolve("ledger.log"), lines);
        AppendOnlyLedger bad = AppendOnlyLedger.openDegraded(dir.resolve("ledger.log"));
        CompliancePurgeService cps = newCompliance(bad, newHolds());
        TamperException ex = assertThrows(TamperException.class,
                () -> cps.execute(new CompliancePurgeRequest("rx", "r", null, 1L, 1L, false)));
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=破坏账本上发起合规清除"
                + " 判定依据=" + ex.getMessage() + " 最终状态=明确拒绝");
    }

    @Test
    void rangeSelectorOnlyPurgesRange(TestInfo info) {
        AppendOnlyLedger l = newLedger();
        long now = System.currentTimeMillis();
        for (int i = 1; i <= 5; i++) {
            l.append("k" + i, payload("u" + i, now), now);
        }
        CompliancePurgeService cps = newCompliance(l, newHolds());
        CompliancePurgeResult r = cps.execute(new CompliancePurgeRequest("rr", "r",
                null, 2L, 4L, false));
        assertEquals(java.util.List.of(2L, 3L, 4L), r.purgedSequences());
        assertNotNull(l.at(1).orElseThrow().payloadJson());
        assertNotNull(l.at(5).orElseThrow().payloadJson());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=序号范围[2,4]"
                + " 判定依据=仅闭区间命中 最终状态=2,3,4清除，1,5保留，选择器=" + r.selector());
    }
}
