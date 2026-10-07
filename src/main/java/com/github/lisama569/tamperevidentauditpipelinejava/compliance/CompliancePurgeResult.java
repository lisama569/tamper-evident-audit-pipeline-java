package com.github.lisama569.tamperevidentauditpipelinejava.compliance;

import java.util.List;

/**
 * 合规清除的可解释结果。预演（dryRun=true）与正式执行返回相同结构；
 * idempotentReplay=true 表示该 requestId 此前已执行过，本次直接回放首次结论，未再做任何清除。
 */
public record CompliancePurgeResult(String requestId, String reason, boolean dryRun,
                                    boolean idempotentReplay, long evaluatedAtMs,
                                    String selector,
                                    List<PurgeItemOutcome> items,
                                    List<Long> purgedSequences,
                                    List<Long> blockedByLegalHold,
                                    List<Long> alreadyPurgedSequences) {

    public int purgedCount() {
        return purgedSequences.size();
    }

    public int blockedCount() {
        return blockedByLegalHold.size();
    }
}
