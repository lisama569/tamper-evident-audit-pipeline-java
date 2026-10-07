package com.github.lisama569.tamperevidentauditpipelinejava.compliance;

/**
 * 单条记录在一次合规清除中的处置结论（预演与执行共用同一份判定逻辑，保证两者结论一致）。
 */
public enum PurgeDecision {
    /** 本次将执行（或已经执行）合规清除。 */
    PURGE_COMPLIANCE,
    /** 命中法律保留，最高优先级，一律挡住不得清除。 */
    BLOCKED_BY_LEGAL_HOLD,
    /** 此前已被清除（到期或更早的合规请求），本次不重复处理。 */
    ALREADY_PURGED,
    /** 在选择器命中范围内但未到期等原因不动作——当前策略下命中即清，保留枚举位用于可解释扩展。 */
    RETAINED
}
