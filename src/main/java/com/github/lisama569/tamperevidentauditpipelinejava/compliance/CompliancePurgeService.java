package com.github.lisama569.tamperevidentauditpipelinejava.compliance;

import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.StoredEvent;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.TamperException;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.LegalHoldService;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.PurgeSource;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 主动合规清除：带请求标识与原因，按主体或记录序号范围发起；支持预演与执行，二者同参结论一致。
 *
 * <p>仲裁优先级（每条记录的结论都可解释）：
 * <ol>
 *   <li><b>法律保留（最高）</b>：命中 hold 的记录一律 BLOCKED_BY_LEGAL_HOLD，任何情况不清；</li>
 *   <li><b>已清除不重复处理</b>：ALREADY_PURGED_EXPIRY / ALREADY_PURGED_COMPLIANCE；</li>
 *   <li><b>合规清除 &gt; 保留到期</b>：命中请求范围且未被 hold 挡住的记录按 COMPLIANCE 清除，
 *       即使它本来还没到期；一条“快到期又被合规命中”的记录来源记为 COMPLIANCE。</li>
 * </ol>
 *
 * <p>幂等：请求参数与首次评估边界（当时的最大数据序号）持久化到 purge-requests.log；
 * 同一 requestId 重复提交（含重启后）直接返回首次结论（idempotentReplay=true），
 * 不会重复清除、不会因新增记录而产生额外处理；同 id 不同参数 → {@link DuplicatePurgeRequestException}。
 * 执行中途崩溃：链内带 requestId 的 PURGE 帧本身就是已完成证据，重跑会补齐剩余部分，最终集合不变。
 */
public class CompliancePurgeService {

    private final AppendOnlyLedger ledger;
    private final LegalHoldService holds;
    private final PurgeRequestStore store;

    public CompliancePurgeService(AppendOnlyLedger ledger, LegalHoldService holds, Path storageDir) {
        this.ledger = ledger;
        this.holds = holds;
        this.store = new PurgeRequestStore(storageDir.resolve("purge-requests.log"));
    }

    /** 预演：给出每条命中记录的结论与依据，不改动任何留存内容（不写帧、不删 DEK）。 */
    public CompliancePurgeResult preview(CompliancePurgeRequest request) {
        return evaluate(request, true);
    }

    /** 执行：同一 requestId 幂等，重复提交（含进程重启后）返回与首次完全一致的结论。 */
    public CompliancePurgeResult execute(CompliancePurgeRequest request) {
        return evaluate(request, false);
    }

    private CompliancePurgeResult evaluate(CompliancePurgeRequest request, boolean dryRun) {
        validate(request);
        CompliancePurgeRequest effective = request.dryRun() == dryRun
                ? request
                : new CompliancePurgeRequest(request.requestId(), request.reason(), request.subject(),
                        request.fromSequence(), request.toSequence(), dryRun);

        synchronized (ledger) {
            if (ledger.isClosed()) {
                throw new TamperException(ledger.firstTamperedSequence(),
                        "账本已因检测到破坏而关闭，最早受影响序号=" + ledger.firstTamperedSequence()
                                + "，拒绝" + (dryRun ? "预演" : "执行") + "合规清除请求 " + request.requestId());
            }
            // 0) 先校验参数指纹：同 requestId 不同参数必须明确报冲突，哪怕结论已存在
            var recorded = store.recordedRequest(effective.requestId());
            if (recorded != null) {
                recorded.requireSame(effective);
            }
            // 1) 参数一致且该操作（预演/执行）已有最终结论：幂等直接返回（重启后同样成立，不依赖内存）
            var prior = store.recordedResult(effective.requestId(), dryRun);
            if (prior != null) {
                return prior;
            }

            // 2) 首次请求固定评估边界（当时的最大数据序号），之后新追加的记录不属于本次请求
            long evalUpTo;
            if (recorded == null) {
                evalUpTo = ledger.nextSequence() - 1L;
                store.recordRequest(effective, evalUpTo);
            } else {
                evalUpTo = recorded.evalUpToSequence();
            }

            // 3) 逐条评估
            List<RecordPurgeItem> items = new ArrayList<>();
            List<Long> purged = new ArrayList<>();
            List<Long> blocked = new ArrayList<>();
            List<Long> already = new ArrayList<>();
            List<StoredEvent> events = ledger.all();
            for (StoredEvent e : events) {
                if (e.sequence() > evalUpTo) {
                    continue; // 首次评估之后才写入的记录不属于本请求，保证重放无额外处理
                }
                if (!inScope(e, effective)) {
                    continue;
                }
                // 优先级 1：法律保留最高
                if (holds.isHeld(e)) {
                    blocked.add(e.sequence());
                    items.add(new RecordPurgeItem(e.sequence(), RecordDecision.BLOCKED_BY_LEGAL_HOLD,
                            "subject=" + safeSubject(e) + " 命中现行法律保留模式；法律保留优先级最高，一律不清",
                            null));
                    continue;
                }
                // 优先级 2：已清除不重复处理，区分历史来源
                if (e.purged()) {
                    // 执行中途崩溃重放：带本 requestId 的 PURGE 帧说明该记录是“本次请求已完成的那部分”，
                    // 计入 purged（不是 ALREADY），剩余未清记录继续补清，最终集合与一次成功一致。
                    if (!dryRun && effective.requestId().equals(e.purgeRequestId())) {
                        purged.add(e.sequence());
                        items.add(new RecordPurgeItem(e.sequence(), RecordDecision.PURGED,
                                "崩溃恢复：该记录的 PURGE 帧(requestId 与本次一致)已落盘，计入本次请求结论；明文此前已加密擦除",
                                "COMPLIANCE"));
                        continue;
                    }
                    boolean compliance = e.purgeSource() == PurgeSource.COMPLIANCE;
                    already.add(e.sequence());
                    RecordDecision d = compliance
                            ? RecordDecision.ALREADY_PURGED_COMPLIANCE
                            : RecordDecision.ALREADY_PURGED_EXPIRY;
                    String src = compliance ? "COMPLIANCE" : "EXPIRY";
                    items.add(new RecordPurgeItem(e.sequence(), d,
                            "该记录已于 " + e.purgedAtMs() + " 被"
                                    + (compliance ? "合规清除(requestId=" + e.purgeRequestId() + ")" : "保留到期清除")
                                    + "，不重复处理", src));
                    continue;
                }
                // 优先级 3：合规清除高于保留到期——命中即按 COMPLIANCE 清，不管是否已到期
                if (dryRun) {
                    purged.add(e.sequence());
                    items.add(new RecordPurgeItem(e.sequence(), RecordDecision.WILL_PURGE,
                            "未命中法律保留；合规清除优先级高于保留到期，执行后将按 COMPLIANCE 加密擦除（明文不可恢复，链内留痕）",
                            "COMPLIANCE"));
                } else {
                    // 崩溃在多条之间：已带本 requestId 的 PURGE 帧会使该记录以 purged 形态出现在上面的分支；
                    // 走到这里说明尚未清除，执行后最终集合与无中断时一致。
                    ledger.markPurged(e.sequence(), PurgeSource.COMPLIANCE,
                            effective.requestId(), effective.reason());
                    purged.add(e.sequence());
                    items.add(new RecordPurgeItem(e.sequence(), RecordDecision.PURGED,
                            "未命中法律保留；合规清除优先级高于保留到期，已按 COMPLIANCE 加密擦除，"
                                    + "PURGE 帧含 requestId/reason，历史存在性仍可审计", "COMPLIANCE"));
                }
            }

            List<Long> retained = new ArrayList<>(blocked);
            CompliancePurgeResult result = new CompliancePurgeResult(effective.requestId(),
                    effective.reason(), dryRun, false, System.currentTimeMillis(),
                    selectorDescribe(effective, evalUpTo), List.copyOf(items),
                    List.copyOf(purged), List.copyOf(blocked), List.copyOf(already),
                    List.copyOf(retained));
            // 4) 预演结论也持久化：同 id 第二次预演/后续执行返回与首次完全一致的结论
            store.recordResult(result);
            return result;
        }
    }

    private boolean inScope(StoredEvent e, CompliancePurgeRequest r) {
        boolean rangeSelectorAbsent = r.fromSequence() == null && r.toSequence() == null;
        boolean subjectSelectorAbsent = r.subject() == null || r.subject().isEmpty();
        boolean inRange = !rangeSelectorAbsent
                && (r.fromSequence() == null || e.sequence() >= r.fromSequence())
                && (r.toSequence() == null || e.sequence() <= r.toSequence());
        boolean subjectMatches = !subjectSelectorAbsent
                && e.payloadJson() != null
                && containsSubject(e.payloadJson(), r.subject());
        // 两个选择器都给出时取交集语义：主体 AND 范围；只给一个时按该选择器命中
        if (!rangeSelectorAbsent && !subjectSelectorAbsent) {
            return inRange && subjectMatches;
        }
        return inRange || subjectMatches;
    }

    private static boolean containsSubject(String payloadJson, String pattern) {
        String s = LegalHoldService.subjectOf(payloadJson);
        return s != null && s.contains(pattern);
    }

    private static String safeSubject(StoredEvent e) {
        String s = e.payloadJson() == null ? null : LegalHoldService.subjectOf(e.payloadJson());
        return s == null ? "?" : s;
    }

    private static String selectorDescribe(CompliancePurgeRequest r, long evalUpTo) {
        List<String> parts = new ArrayList<>();
        if (r.subject() != null && !r.subject().isEmpty()) {
            parts.add("subject~=" + r.subject());
        }
        if (r.fromSequence() != null || r.toSequence() != null) {
            parts.add("seq∈[" + (r.fromSequence() == null ? "1" : r.fromSequence())
                    + "," + (r.toSequence() == null ? "*" : r.toSequence()) + "]");
        }
        parts.add("evalUpToSeq=" + evalUpTo);
        return String.join(" ", parts);
    }

    private void validate(CompliancePurgeRequest r) {
        if (r == null) {
            throw new IllegalArgumentException("合规清除请求不能为空");
        }
        if (r.requestId() == null || r.requestId().isBlank()) {
            throw new IllegalArgumentException("合规清除请求标识 requestId 不能为空");
        }
        if (r.reason() == null || r.reason().isBlank()) {
            throw new IllegalArgumentException("合规清除原因 reason 不能为空");
        }
        boolean hasSubject = r.subject() != null && !r.subject().isEmpty();
        boolean hasRange = r.fromSequence() != null || r.toSequence() != null;
        if (!hasSubject && !hasRange) {
            throw new IllegalArgumentException("合规清除必须指定主体(subject)或记录序号范围(fromSequence/toSequence)");
        }
        if (r.fromSequence() != null && r.fromSequence() < 1L) {
            throw new IllegalArgumentException("fromSequence 必须 >= 1");
        }
        if (r.toSequence() != null && r.toSequence() < 1L) {
            throw new IllegalArgumentException("toSequence 必须 >= 1");
        }
        if (r.fromSequence() != null && r.toSequence() != null && r.fromSequence() > r.toSequence()) {
            throw new IllegalArgumentException("非法序号范围: fromSequence > toSequence");
        }
    }

}
