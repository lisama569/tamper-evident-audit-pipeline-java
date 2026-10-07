package com.github.lisama569.tamperevidentauditpipelinejava.compliance;

/**
 * 单条记录的清除评估条目：结论、依据与（已清除时的）清除来源。
 */
public record RecordPurgeItem(long sequence, RecordDecision decision, String rationale,
                              String purgeSource) {
}
