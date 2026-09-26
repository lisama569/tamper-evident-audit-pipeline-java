package com.github.lisama569.tamperevidentauditpipelinejava.retention;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.StoredEvent;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 保留策略执行。
 *
 * <p>优先级（从高到低，结论可解释）：
 * <ol>
 *   <li><b>法律保留（LEGAL_HOLD）</b>：命中 hold 的记录无论多旧都不得清除 → retainedByLegalHold。</li>
 *   <li><b>保留到期（RETENTION_EXPIRY）</b>：事件时间早于 now - retentionDays 且未被 hold 命中 → 清除。</li>
 *   <li><b>未到期（WITHIN_RETENTION）</b>：其余记录保留 → retainedNotExpired。</li>
 * </ol>
 *
 * <p>清除方式为加密擦除：在哈希链内追加 PURGE 标记帧后删除每条记录独立的 DEK；
 * envelope（序号/幂等键/哈希/时间）仍可被哈希链验证，明文不可恢复。
 * 已清除的记录不会被重复处理。
 */
public class RetentionService {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AppendOnlyLedger ledger;
    private final LegalHoldService holds;
    private final int retentionDays;
    private final Path keyDir;

    public RetentionService(AppendOnlyLedger ledger, LegalHoldService holds,
                            int retentionDays, Path keyDir) {
        this.ledger = ledger;
        this.holds = holds;
        this.retentionDays = retentionDays;
        this.keyDir = keyDir;
    }

    public int retentionDays() {
        return retentionDays;
    }

    /**
     * 执行一次保留策略。边界说明：以事件 occurredAt 为准（载荷缺失时回退到账本 storedAt），
     * cutoff = 评估时刻 - retentionDays；{@code occurredAt < cutoff} 视为到期；
     * 等于 cutoff（恰好在边界上）的记录保留，避免临界时刻结论反复。
     */
    public PurgeResult enforceNow() {
        long evaluatedAt = System.currentTimeMillis();
        long cutoff = evaluatedAt - Duration.ofDays(retentionDays).toMillis();

        List<Long> purged = new ArrayList<>();
        List<Long> held = new ArrayList<>();
        List<Long> kept = new ArrayList<>();

        List<StoredEvent> events;
        synchronized (ledger) {
            events = ledger.all();
        }
        for (StoredEvent e : events) {
            long decisionTime = eventTimeOrStored(e);
            // 1) 法律保留优先：即使已到期也不得清除
            if (holds.isHeld(e)) {
                held.add(e.sequence());
                continue;
            }
            // 2) 已清除（幂等重放）不计入任何动作清单
            if (e.purged()) {
                continue;
            }
            // 3) 到期判定
            if (decisionTime < cutoff) {
                ledger.markPurged(e.sequence());
                purged.add(e.sequence());
            } else {
                kept.add(e.sequence());
            }
        }
        return new PurgeResult("RETENTION_EXPIRY days=" + retentionDays
                + " cutoffMs=" + cutoff
                + " cutoff=" + Instant.ofEpochMilli(cutoff), evaluatedAt, purged, held, kept);
    }

    private static long eventTimeOrStored(StoredEvent e) {
        if (e.payloadJson() != null) {
            try {
                JsonNode n = MAPPER.readTree(e.payloadJson());
                JsonNode t = n.get("occurredAtMs");
                if (t != null && t.isNumber()) {
                    return t.asLong();
                }
            } catch (Exception ignore) {
                // 载荷无法解析时回退到写入时间
            }
        }
        return e.storedAtMs();
    }
}
