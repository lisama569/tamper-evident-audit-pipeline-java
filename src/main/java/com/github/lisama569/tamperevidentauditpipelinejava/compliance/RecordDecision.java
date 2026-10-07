package com.github.lisama569.tamperevidentauditpipelinejava.compliance;

/**
 * 合规清除对单条记录的决策（结果里要能看出每条为什么留、为什么清）。
 */
public enum RecordDecision {
    WILL_PURGE,                  // 预演：命中、将被合规清除
    PURGED,                      // 执行：已按合规清除完成
    BLOCKED_BY_LEGAL_HOLD,       // 命中法律保留，被挡下
    ALREADY_PURGED_EXPIRY,       // 此前已被到期清除，不重复处理
    ALREADY_PURGED_COMPLIANCE,   // 此前已被合规清除，不重复处理
    OUT_OF_SCOPE_RETAINED,       // 未命中请求范围（未到期），保留
    OUT_OF_SCOPE_EXPIRED         // 未命中请求范围但已到期（下次到期执行处理）
}
