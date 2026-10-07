package com.github.lisama569.tamperevidentauditpipelinejava.compliance;

/**
 * 一次合规清除请求（主动发起、可解释、幂等）。
 *
 * <p>选择器二选一（也可同时给，取交集为空时不命中任何记录）：
 * <ul>
 *   <li>{@code subjectPattern}：按主体子串匹配（大小写敏感），与法律保留的匹配方式一致；</li>
 *   <li>{@code fromSeqInclusive}/{@code toSeqInclusive}：按 DATA 记录序号范围（闭区间，边界可只给一边）。</li>
 * </ul>
 * 同一个 {@code requestId} 重复提交：第二次直接返回第一次的结论，不重复清除、不产生额外处理；
 * 若用同一 requestId 携带不同请求体，则拒绝为冲突（409）。
 */
public record CompliancePurgeRequest(String requestId, String reason, String subjectPattern,
                                     Long fromSeqInclusive, Long toSeqInclusive, boolean dryRun) {

    public boolean hasSubjectSelector() {
        return subjectPattern != null && !subjectPattern.isEmpty();
    }

    public boolean hasRangeSelector() {
        return fromSeqInclusive != null || toSeqInclusive != null;
    }
}
