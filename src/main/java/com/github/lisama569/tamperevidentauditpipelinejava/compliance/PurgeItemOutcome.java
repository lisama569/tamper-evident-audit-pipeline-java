package com.github.lisama569.tamperevidentauditpipelinejava.compliance;

/**
 * 一条记录的清除结果明细：序号、处置结论、原因说明、清除来源。
 * source 仅在真正被本次合规清除时为 COMPLIANCE；已清除记录按其历史标记来源回报。
 */
public record PurgeItemOutcome(long sequence, PurgeDecision decision, String detail,
                               String purgeSource, String requestId) {

    public static PurgeItemOutcome purge(long seq, String requestId) {
        return new PurgeItemOutcome(seq, PurgeDecision.PURGE_COMPLIANCE,
                "合规清除命中，未处于法律保留，执行加密擦除", "COMPLIANCE", requestId);
    }

    public static PurgeItemOutcome blocked(long seq, String why) {
        return new PurgeItemOutcome(seq, PurgeDecision.BLOCKED_BY_LEGAL_HOLD, why, null, null);
    }

    public static PurgeItemOutcome alreadyPurged(long seq, String source, String requestId) {
        return new PurgeItemOutcome(seq, PurgeDecision.ALREADY_PURGED,
                "该记录此前已清除（来源=" + source + "），本次不重复处理", source, requestId);
    }
}
