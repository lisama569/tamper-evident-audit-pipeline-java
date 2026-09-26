package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.lisama569.tamperevidentauditpipelinejava.config.PipelineProperties;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.AuditEvent;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.HmacSigner;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.PurgeReport;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.LegalHoldStore;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.RetentionService;
import com.github.lisama569.tamperevidentauditpipelinejava.storage.CompactionJournal;
import com.github.lisama569.tamperevidentauditpipelinejava.storage.FileAppendStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 保留边界、法律保留优先级、逻辑墓碑与物理清除（含重启后篡改检测仍有效）。
 */
class RetentionServiceTest {

    private static final Logger log = LoggerFactory.getLogger(RetentionServiceTest.class);
    private static final Instant T0 = Instant.parse("2026-09-26T00:00:00Z");

    private ObjectMapper mapper() {
        ObjectMapper m = new ObjectMapper();
        m.registerModule(new JavaTimeModule());
        m.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return m;
    }

    record Ctx(FileAppendStore store, LegalHoldStore holds, CompactionJournal journal,
               RetentionService retention) {
    }

    private Ctx ctx(Path dir) throws Exception {
        ObjectMapper mapper = mapper();
        FileAppendStore store = new FileAppendStore(dir, new HmacSigner("s"), mapper);
        store.initialize();
        LegalHoldStore holds = new LegalHoldStore(dir, mapper, new HmacSigner("s"));
        holds.initialize();
        CompactionJournal journal = new CompactionJournal(dir, mapper, new HmacSigner("s"));
        journal.initialize();
        PipelineProperties props = new PipelineProperties();
        // 用真实系统时钟：记录 appendedAt 也是真实 now，端到端清除用 retentionDays=0 不可行，
        // 因此端到端用例会以“超大/超小保留期 + 显式 now”的方式调用 purgeExpired(now)。
        RetentionService retention = new RetentionService(store, holds, journal, props);
        return new Ctx(store, holds, journal, retention);
    }

    private AuditEvent ev(String key, int retentionDays) {
        return new AuditEvent(key, "s", "T", T0.minus(30, ChronoUnit.DAYS), "a", "b",
                retentionDays, Map.of());
    }

    @Test
    void retentionBoundary_offByOneDay(@TempDir Path base) throws Exception {
        Ctx c = ctx(base.resolve("boundary"));
        // 两条记录都在“现在”留存：retentionDays=90 未到期；为验证边界，
        // 直接对 isRetentionExpired 用不同 appendedAt 做 off-by-one 判定。
        StoredRecord justExpired = new StoredRecord(1, "r1", ev("a", 1),
                T0.plus(10, ChronoUnit.DAYS).minus(1, ChronoUnit.DAYS), "p", "h");
        StoredRecord notYet = new StoredRecord(2, "r2", ev("b", 1),
                T0.plus(10, ChronoUnit.DAYS).minus(1, ChronoUnit.DAYS).plusSeconds(1), "p", "h");
        Instant now = T0.plus(10, ChronoUnit.DAYS);
        assertTrue(c.retention().isRetentionExpired(justExpired, now),
                "appendedAt + 1天 <= now （恰好到期）=> 可清除");
        assertFalse(c.retention().isRetentionExpired(notYet, now),
                "差 1 秒未到 appendedAt+1天 => 不可清除");
        log.info("【保留边界】判定依据 appendedAt+retentionDays<=now；恰好到期=true，差1秒=false");

        // 端到端：留存两条，retentionDays 分别为 1（到期）和 30（未到期）
        Ctx c2 = ctx(base.resolve("e2e"));
        c2.store().append(ev("expired", 1));
        c2.store().append(ev("fresh", 3650));
        PurgeReport report = c2.retention().purgeExpired(RetentionService.MODE_LOGICAL,
                Instant.now().plus(2, ChronoUnit.DAYS));
        assertEquals(List.of(1L), report.eligible());
        assertTrue(c2.store().erasedSeqs().contains(1L));
        assertFalse(c2.store().erasedSeqs().contains(2L));
        assertTrue(c2.store().get(1).isEmpty());
        assertTrue(c2.store().get(2).isPresent());
        log.info("【到期清除-端到端】eligible={} blocked={} 最终 seq1墓碑 seq2保留",
                report.eligible(), report.blockedByHold());
    }

    @Test
    void legalHoldBlocksBothExpiryAndComplianceErasure(@TempDir Path base) throws Exception {
        Ctx c = ctx(base.resolve("hold"));
        c.store().append(ev("a", 1));
        c.store().append(ev("b", 1));
        c.holds().place(1, "CASE-42", "诉讼保全", "compliance-officer");

        PurgeReport expiry = c.retention().purgeExpired(RetentionService.MODE_LOGICAL,
                Instant.now().plus(2, ChronoUnit.DAYS));
        assertEquals(List.of(2L), expiry.eligible());
        assertEquals(List.of(1L), expiry.blockedByHold(), "法律保留必须阻止到期清除");
        assertTrue(c.store().get(1).isPresent(), "被保留记录不得被清除");
        assertTrue(c.store().get(2).isEmpty());
        log.info("【法律保留-到期】blocked={} eligible={} seq1 留存", expiry.blockedByHold(), expiry.eligible());

        PurgeReport compliance = c.retention().complianceErase(Set.of(1L), "gdpr", RetentionService.MODE_ERASURE);
        assertEquals(List.of(1L), compliance.blockedByHold());
        assertTrue(compliance.purged().isEmpty());
        assertTrue(c.store().get(1).isPresent(), "即使合规清除请求，法律保留中的记录也不得清除");
        log.info("【法律保留-合规清除】seq1 被 CASE-42 阻止，记录仍留存");

        assertTrue(c.holds().release(1, "CASE-42"));
        PurgeReport after = c.retention().complianceErase(Set.of(1L), "gdpr", RetentionService.MODE_ERASURE);
        assertTrue(after.purged().contains(1L));
        log.info("【解除保留后清除】seq1 在解除法律保留后物理清除成功");
    }

    @Test
    void physicalErasureRewritesChainAndSurvivorsStillVerify(@TempDir Path base) throws Exception {
        Path dir = base.resolve("erasure");
        Ctx c = ctx(dir);
        for (int i = 1; i <= 4; i++) {
            c.store().append(ev("e" + i, 90));
        }
        PurgeReport report = c.retention().complianceErase(Set.of(2L, 3L), "req", RetentionService.MODE_ERASURE);
        assertEquals(List.of(2L, 3L), report.purged());
        assertTrue(c.store().get(1).isPresent());
        assertTrue(c.store().get(4).isPresent());
        assertTrue(c.store().get(2).isEmpty());
        assertEquals(2, c.store().all().size());
        assertEquals(1, c.journal().entries().size());
        assertEquals(List.of(2L, 3L), c.journal().entries().get(0).removedSeqs());
        log.info("【物理清除】purged={} 幸存者={} 凭证={}", report.purged(),
                c.store().all().stream().map(StoredRecord::seq).toList(),
                c.journal().entries().get(0).id());

        FileAppendStore reopened = new FileAppendStore(dir, new HmacSigner("s"), mapper());
        reopened.initialize();
        assertFalse(reopened.isSealed(), "授权清除后重启不应密封");
        assertEquals(2, reopened.all().size());
        assertTrue(reopened.erasedSeqs().containsAll(Set.of(2L, 3L)));
        log.info("【清除后重启】存储正常加载未密封；erasedSeqs={}", reopened.erasedSeqs());

        StoredRecord added = reopened.append(ev("e5", 90));
        assertEquals(5, added.seq());
        FileAppendStore reopened2 = new FileAppendStore(dir, new HmacSigner("s"), mapper());
        reopened2.initialize();
        assertFalse(reopened2.isSealed());
        assertEquals(3, reopened2.all().size());
        log.info("【清除后追加】压实后新追加 seq=5，重启校验链连续，记录数=3");
    }
}
