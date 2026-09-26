package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.LegalHoldService;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.PurgeResult;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.RetentionService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 保留边界与法律保留优先级测试。
 *
 * <p>清除判定以载荷中的 occurredAtMs 为准：occurredAt &lt; now-retentionDays 才清除；
 * 恰在边界（== cutoff）保留。命中法律保留的记录即使已到期也保留。
 */
class RetentionServiceTest {

    private static final Logger LOG = Logger.getLogger(RetentionServiceTest.class.getName());

    private @TempDir Path dir;

    private String payload(long occurredAtMs, String subject) {
        return "{\"subject\":\"" + subject + "\",\"occurredAtMs\":" + occurredAtMs + "}";
    }

    @Test
    void expiredArePurgedAndFreshAreKept(TestInfo info) {
        AppendOnlyLedger ledger = new AppendOnlyLedger(dir.resolve("ledger.log"));
        RetentionService rs = new RetentionService(ledger,
                new LegalHoldService(dir.resolve("holds.log")), 90, dir.resolve("keys"));
        // 先取到“执行清除时刻”的实际 cutoff，使边界用例不受执行耗时影响
        long cutoff = Long.parseLong(rs.enforceNow().policy().replaceAll(".*cutoffMs=", "").replaceAll("\\D.*", ""));
        long minute = Duration.ofMinutes(1).toMillis();
        ledger.append("k-old", payload(cutoff - minute, "a"), cutoff - minute);     // 早于 cutoff → 清除
        ledger.append("k-edge", payload(cutoff + minute, "b"), cutoff + minute);    // 晚于 cutoff → 保留
        ledger.append("k-new", payload(cutoff + Duration.ofDays(1).toMillis(), "c"),
                cutoff + Duration.ofDays(1).toMillis());

        PurgeResult result = rs.enforceNow();

        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入={cutoff-1, cutoff+1, cutoff+1天}"
                + " 判定依据=" + result.policy()
                + " (occurredAt < cutoffMs 才清除，边界及之后保留) 清除=" + result.purgedSequences() + " 未到期=" + result.retainedNotExpired()
                + " 最终状态=仅cutoff之前的记录被清除，边界(cutoff本身/之后)保留");
        assertTrue(result.purgedSequences().contains(1L));
        assertTrue(result.retainedNotExpired().contains(2L));
        assertTrue(result.retainedNotExpired().contains(3L));
        assertNull(ledger.at(1).orElseThrow().payloadJson());
        assertNotNull(ledger.at(2).orElseThrow().payloadJson());
        assertEquals(-1L, ledger.verify());

        // 再次执行幂等：不重复产生动作
        PurgeResult second = rs.enforceNow();
        assertTrue(second.purgedSequences().isEmpty());
    }

    @Test
    void legalHoldOverridesExpiry(TestInfo info) {
        long now = System.currentTimeMillis();
        AppendOnlyLedger ledger = new AppendOnlyLedger(dir.resolve("ledger.log"));
        ledger.append("k1", payload(now - Duration.ofDays(200).toMillis(), "vip-alice"),
                now - Duration.ofDays(200).toMillis());
        ledger.append("k2", payload(now - Duration.ofDays(200).toMillis(), "bob"),
                now - Duration.ofDays(200).toMillis());

        LegalHoldService holds = new LegalHoldService(dir.resolve("holds.log"));
        holds.addHold("h1", "vip-alice", "诉讼相关");
        RetentionService rs = new RetentionService(ledger, holds, 90, dir.resolve("keys"));
        PurgeResult result = rs.enforceNow();

        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=两条200天前记录, subject=vip-alice被hold"
                + " 判定依据=法律保留优先级高于到期"
                + " 清除=" + result.purgedSequences() + " hold保留=" + result.retainedByLegalHold()
                + " 最终状态=vip-alice保留, bob清除");
        assertTrue(result.retainedByLegalHold().contains(1L));
        assertTrue(result.purgedSequences().contains(2L));
        assertNotNull(ledger.at(1).orElseThrow().payloadJson());
        assertNull(ledger.at(2).orElseThrow().payloadJson());
    }

    @Test
    void removingHoldAllowsLaterPurge(TestInfo info) {
        long now = System.currentTimeMillis();
        AppendOnlyLedger ledger = new AppendOnlyLedger(dir.resolve("ledger.log"));
        ledger.append("k1", payload(now - Duration.ofDays(200).toMillis(), "vip-alice"),
                now - Duration.ofDays(200).toMillis());
        LegalHoldService holds = new LegalHoldService(dir.resolve("holds.log"));
        holds.addHold("h1", "vip-alice", "诉讼");
        RetentionService rs = new RetentionService(ledger, holds, 90, dir.resolve("keys"));

        PurgeResult r1 = rs.enforceNow();
        assertTrue(r1.retainedByLegalHold().contains(1L));
        holds.removeHold("h1");
        PurgeResult r2 = rs.enforceNow();
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定依据=hold移除后到期规则生效"
                + " 最终状态=" + r2.purgedSequences());
        assertTrue(r2.purgedSequences().contains(1L));
    }
}
