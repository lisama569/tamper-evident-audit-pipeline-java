package com.github.lisama569.tamperevidentauditpipelinejava.compliance;

import java.util.List;

/**
 * 合规清除（预演或执行）的可解释结果。
 * 幂等：同一 requestId 重复提交返回与首次完全一致的结论。
 */
public record CompliancePurgeResult(String requestId, String reason, boolean dryRun,
                                    boolean idempotentReplay, long evaluatedAtMs,
                                    String selector,
                                    List<RecordPurgeItem> items,
                                    List<Long> purgedSequences,
                                    List<Long> blockedByLegalHold,
                                    List<Long> alreadyPurged,
                                    List<Long> retainedSequences) {
}
