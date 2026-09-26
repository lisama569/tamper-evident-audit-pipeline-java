package com.github.lisama569.tamperevidentauditpipelinejava.retention;

import com.github.lisama569.tamperevidentauditpipelinejava.config.PipelineProperties;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.PurgeReport;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;
import com.github.lisama569.tamperevidentauditpipelinejava.storage.CompactionEntry;
import com.github.lisama569.tamperevidentauditpipelinejava.storage.CompactionJournal;
import com.github.lisama569.tamperevidentauditpipelinejava.storage.TamperEvidentStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * 保留策略 / 法律保留 / 合规清除的优先级仲裁与执行。
 *
 * <p>优先级（从高到低，明确可解释）：
 * <ol>
 *   <li><b>法律保留（legal hold）</b>：最高优先。处于保留状态的记录在任何模式下都不得清除，
 *       即使保留期已到或收到合规清除请求；</li>
 *   <li><b>合规清除请求（compliance erasure）</b>：次高。若未被法律保留阻止，则按请求清除；</li>
 *   <li><b>保留到期（retention expiry）</b>：最低。仅当记录超过其自身保留期（retentionDays，
 *       基于 appendedAt）且未被法律保留时才清除。</li>
 * </ol>
 *
 * <p>清除模式：
 * <ul>
 *   <li>{@code LOGICAL_TOMBSTONE}（默认）：仅登记墓碑，字节仍在哈希链上，证据最强；</li>
 *   <li>{@code ERASURE}：物理压实，字节从段文件移除并重锚哈希链，凭证永久备案。</li>
 * </ul>
 */
@Service
public class RetentionService {

    private static final Logger log = LoggerFactory.getLogger(RetentionService.class);

    public static final String MODE_LOGICAL = "LOGICAL_TOMBSTONE";
    public static final String MODE_ERASURE = "ERASURE";
    public static final String REASON_EXPIRED = "RETENTION_EXPIRED";
    public static final String REASON_COMPLIANCE = "COMPLIANCE_ERASURE_REQUEST";

    private final TamperEvidentStore store;
    private final LegalHoldStore holds;
    private final CompactionJournal journal;
    private final PipelineProperties props;
    private final Clock clock;

    @org.springframework.beans.factory.annotation.Autowired
    public RetentionService(TamperEvidentStore store,
                            LegalHoldStore holds,
                            CompactionJournal journal,
                            PipelineProperties props) {
        this(store, holds, journal, props, Clock.systemUTC());
    }

    /** 可注入固定时钟的构造器（用于边界测试）。 */
    public RetentionService(TamperEvidentStore store,
                            LegalHoldStore holds,
                            CompactionJournal journal,
                            PipelineProperties props,
                            Clock clock) {
        this.store = store;
        this.holds = holds;
        this.journal = journal;
        this.props = props;
        this.clock = clock;
    }

    /** 判断单条记录的保留期是否已到（基于留存时间 appendedAt + retentionDays）。 */
    public boolean isRetentionExpired(StoredRecord r, Instant now) {
        Instant expireAt = r.appendedAt().plus(Duration.ofDays(r.event().retentionDays()));
        return !now.isBefore(expireAt);
    }

    /**
     * 计算“按保留到期”可清除集合，并把被法律保留阻止的序号单独列出。
     * 不执行任何清除。
     */
    public PurgePlan evaluateExpiry(Instant now) {
        List<Long> eligible = new ArrayList<>();
        List<Long> blocked = new ArrayList<>();
        for (StoredRecord r : store.all()) {
            if (store.erasedSeqs().contains(r.seq())) {
                continue;
            }
            if (!isRetentionExpired(r, now)) {
                continue;
            }
            if (holds.isHeld(r.seq())) {
                blocked.add(r.seq());
            } else {
                eligible.add(r.seq());
            }
        }
        return new PurgePlan(eligible, blocked, REASON_EXPIRED);
    }

    /**
     * 合规清除请求：对给定序号执行清除（法律保留优先，阻止项返回且不清除）。
     */
    public PurgeReport complianceErase(Set<Long> requestedSeqs, String requestedBy, String mode) {
        return runPurge(new TreeSet<>(requestedSeqs), new TreeSet<>(),
                REASON_COMPLIANCE, requestedBy, mode, Instant.now());
    }

    /** 执行保留到期清除。 */
    public PurgeReport purgeExpired(String mode, Instant now) {
        PurgePlan plan = evaluateExpiry(now);
        // 到期评估已把法律保留项排除出 eligible；把这些 blocked 项传入，
        // 使报告与凭证明确区分“到期但被法律保留阻止”的记录。
        return runPurge(new TreeSet<>(plan.eligible()), new TreeSet<>(plan.blockedByHold()),
                REASON_EXPIRED, "system-retention-job", mode, now);
    }

    private PurgeReport runPurge(TreeSet<Long> requested, Set<Long> preBlocked,
                                 String reason, String requestedBy,
                                 String mode, Instant now) {
        if (!MODE_LOGICAL.equals(mode) && !MODE_ERASURE.equals(mode)) {
            throw new IllegalArgumentException("未知清除模式: " + mode);
        }
        Set<Long> blocked = new TreeSet<>(preBlocked);
        Set<Long> toPurge = new TreeSet<>();
        for (Long seq : requested) {
            if (store.erasedSeqs().contains(seq)) {
                continue; // 幂等：已清除
            }
            if (holds.isHeld(seq)) {
                blocked.add(seq); // 法律保留最高优先：明确阻止
            } else {
                toPurge.add(seq);
            }
        }

        if (blocked.isEmpty() == false) {
            log.info("【清除-法律保留阻止】reason={} blocked={}", reason, blocked);
        }

        long prevLastSeq = store.lastSeq();
        String prevLastHash = currentChainTip();

        if (!toPurge.isEmpty()) {
            if (MODE_ERASURE.equals(mode)) {
                store.eraseAndCompact(toPurge);
            } else {
                store.markTombstones(toPurge);
            }
        }

        String newLastHash = currentChainTip();
        journal.append(new CompactionEntry(
                UUID.randomUUID().toString(),
                now.toString(),
                mode,
                reason,
                requestedBy,
                new ArrayList<>(toPurge),
                new ArrayList<>(blocked),
                prevLastSeq,
                prevLastHash,
                store.lastSeq(),
                newLastHash,
                null));

        log.info("【清除完成】mode={} reason={} purged={} blocked={}",
                mode, reason, toPurge, blocked);
        return new PurgeReport(mode, new ArrayList<>(toPurge),
                new ArrayList<>(blocked), new ArrayList<>(toPurge));
    }

    private String currentChainTip() {
        List<StoredRecord> all = store.all();
        return all.isEmpty()
                ? com.github.lisama569.tamperevidentauditpipelinejava.domain.HmacSigner.GENESIS_PREV
                : all.get(all.size() - 1).hash();
    }

    /** 清除计划：可清除项与被法律保留阻止项。 */
    public record PurgePlan(List<Long> eligible, List<Long> blockedByHold, String reason) {
    }
}
