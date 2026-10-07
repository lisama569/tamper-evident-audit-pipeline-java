package com.github.lisama569.tamperevidentauditpipelinejava.ledger;

/**
 * 一条 DATA 记录在链内的清除标记信息（来自 PURGE 帧）。
 *
 * <p>{@code source} 区分两种清除来源：
 * <ul>
 *   <li>{@code RETENTION}：保留到期清除；</li>
 *   <li>{@code COMPLIANCE}：带请求标识与原因主动发起的合规清除。</li>
 * </ul>
 * 即使原始明文已加密擦除不可恢复，该标记仍随哈希链留存，可审计、可证明“这条记录存在过并因何被清”。
 */
public record PurgeMark(long dataSequence, String source, String requestId, String reason,
                        long storedAtMs) {

    public static final String SOURCE_RETENTION = "RETENTION";
    public static final String SOURCE_COMPLIANCE = "COMPLIANCE";

    public boolean compliance() {
        return SOURCE_COMPLIANCE.equals(source);
    }
}
