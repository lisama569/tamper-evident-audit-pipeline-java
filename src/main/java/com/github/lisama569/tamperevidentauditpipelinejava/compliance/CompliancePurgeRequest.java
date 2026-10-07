package com.github.lisama569.tamperevidentauditpipelinejava.compliance;

/**
 * 一次主动合规清除请求（带请求标识与原因）。
 *
 * @param requestId    请求标识：重复提交用于幂等
 * @param reason       清除原因（审计留痕）
 * @param subject      按主体清除时的主体匹配串；null 表示不按主体
 * @param fromSequence 按记录序号范围清除的起点（含）；null 表示不限制
 * @param toSequence   按记录序号范围清除的终点（含）；null 表示不限制
 * @param dryRun       true=仅预演，不改动任何留存内容
 */
public record CompliancePurgeRequest(String requestId, String reason, String subject,
                                     Long fromSequence, Long toSequence, boolean dryRun) {
}
