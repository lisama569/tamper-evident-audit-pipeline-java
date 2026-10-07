package com.github.lisama569.tamperevidentauditpipelinejava.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.lisama569.tamperevidentauditpipelinejava.config.PipelineProperties;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.HttpForwarder;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.OutboxEntry;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.OutboxStore;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.RetryDispatcher;
import com.github.lisama569.tamperevidentauditpipelinejava.ingest.EventNormalizer;
import com.github.lisama569.tamperevidentauditpipelinejava.ingest.NormalizedEvent;
import com.github.lisama569.tamperevidentauditpipelinejava.ingest.ValidationException;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.StoredEvent;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.TamperException;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.VerifyResult;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.CompliancePurgeRequest;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.CompliancePurgeResult;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.CompliancePurgeService;
import com.github.lisama569.tamperevidentauditpipelinejava.model.IngestResult;
import com.github.lisama569.tamperevidentauditpipelinejava.model.RejectReason;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.LegalHold;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.LegalHoldService;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.PurgeResult;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.RetentionService;
import com.fasterxml.jackson.databind.JsonNode;

import java.net.http.HttpClient;
import java.nio.file.Path;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 审计流水线门面。
 *
 * <p>ingest 顺序（全程结论明确）：
 * <ol>
 *   <li>归一化/校验：失败按 {@link RejectReason} 分类拒绝，不静默丢弃；</li>
 *   <li>稳定幂等键查账本：命中 → 返回 duplicate（不重复写入、不重复转发）；</li>
 *   <li>账本追加（哈希链，串行、落盘）：若账本已因篡改关闭 → LEDGER_TAMPERED 拒绝；</li>
 *   <li>outbox 登记（与追加紧邻，崩溃重放保证：账本有记录而 outbox 缺登记时，
 *       下一次进程启动由 {@link #repairOutbox()} 补齐，转发不丢）。</li>
 * </ol>
 */
public class AuditPipelineService {

    private static final Logger LOG = Logger.getLogger(AuditPipelineService.class.getName());

    private final PipelineProperties props;
    private final ObjectMapper mapper;
    private final EventNormalizer normalizer;
    private final AppendOnlyLedger ledger;
    private final OutboxStore outbox;
    private final LegalHoldService holds;
    private final RetentionService retention;
    private final CompliancePurgeService compliance;
    private final RetryDispatcher dispatcher;

    public AuditPipelineService(PipelineProperties props, ObjectMapper mapper) {
        this.props = props;
        this.mapper = mapper;
        Path dir = props.getStorageDir();
        this.normalizer = new EventNormalizer(props.getMaxFutureSkewMs());
        // 降级打开：即便账本检测到破坏，服务仍可启动（只读），新写入通过 LEDGER_TAMPERED 明确拒绝
        this.ledger = AppendOnlyLedger.openDegraded(dir.resolve("ledger.log"));
        if (ledger.isClosed()) {
            LOG.severe(() -> "账本已因篡改关闭(最早受影响序号=" + ledger.firstTamperedSequence()
                    + ")；服务以只读降级模式启动，拒绝一切新追加");
        }
        this.outbox = new OutboxStore(dir.resolve("outbox.log"));
        this.holds = new LegalHoldService(dir.resolve("holds.log"));
        this.retention = new RetentionService(ledger, holds, props.getRetentionDays(),
                dir.resolve("keys"));
        this.compliance = new CompliancePurgeService(ledger, holds,
                dir.resolve("compliance-requests.log"));
        HttpForwarder forwarder = new HttpForwarder(props.getForwardUrl(),
                HttpClient.newHttpClient(), props.getForwardTimeoutMs());
        this.dispatcher = new RetryDispatcher(outbox, forwarder, props.getRetryMaxAttempts(),
                props.getRetryInitialDelayMs(), props.getRetryMaxDelayMs(),
                props.getDispatchIntervalMs(), props.getInflightRecoverMs());
        repairOutbox();
        if (props.isAutoForward()) {
            dispatcher.start();
        }
    }

    public IngestResult ingest(JsonNode raw) {
        NormalizedEvent event;
        try {
            event = normalizer.normalize(raw);
        } catch (ValidationException e) {
            LOG.info(() -> "[INGEST] 输入=" + raw + " 判定=拒绝 reason=" + e.getReason()
                    + " 依据=" + e.getMessage());
            return IngestResult.rejected(e.getReason(), e.getMessage());
        }

        String key = EventNormalizer.idempotencyKey(event.source(), event.eventId());

        synchronized (ledger) {
            if (ledger.isClosed()) {
                String why = "账本已因检测到篡改而关闭，最早受影响序号=" + ledger.firstTamperedSequence();
                LOG.warning(() -> "[INGEST] 判定=拒绝 reason=LEDGER_TAMPERED 依据=" + why);
                return IngestResult.rejected(RejectReason.LEDGER_TAMPERED, why);
            }
            var existing = ledger.findByIdempotencyKey(key);
            if (existing.isPresent()) {
                LOG.info(() -> "[INGEST] 输入 source=" + event.source() + " eventId=" + event.eventId()
                        + " 判定=幂等重复 sequence=" + existing.get().sequence() + " 最终状态=ACCEPTED_DUPLICATE");
                return IngestResult.duplicate(existing.get().sequence(), key);
            }

            String payload = canonicalPayload(event);
            StoredEvent stored;
            try {
                stored = ledger.append(key, payload, event.occurredAtMs());
            } catch (TamperException t) {
                LOG.warning(() -> "[INGEST] 判定=拒绝 reason=LEDGER_TAMPERED 依据=" + t.getMessage());
                return IngestResult.rejected(RejectReason.LEDGER_TAMPERED, t.getMessage());
            } catch (IllegalStateException ise) {
                LOG.log(Level.WARNING, "[INGEST] 账本写入异常", ise);
                return IngestResult.rejected(RejectReason.INTERNAL_ERROR, ise.getMessage());
            }
            // 追加成功后登记 outbox；若登记失败，repairOutbox() 会在重启时补齐，转发不丢。
            try {
                outbox.register(stored.sequence(), key, payload);
            } catch (RuntimeException re) {
                LOG.log(Level.SEVERE,
                        "[INGEST] outbox 登记失败 sequence=" + stored.sequence() + "，将在下次启动时修复", re);
            }
            LOG.info(() -> "[INGEST] 输入 source=" + event.source() + " eventId=" + event.eventId()
                    + " 判定=新事件 sequence=" + stored.sequence() + " key=" + key
                    + " 最终状态=ACCEPTED_NEW");
            return IngestResult.accepted(stored.sequence(), key);
        }
    }

    public PurgeResult enforceRetention() {
        if (ledger.isClosed()) {
            throw new TamperException(ledger.firstTamperedSequence(),
                    "账本已因篡改关闭，最早受影响序号=" + ledger.firstTamperedSequence() + "，拒绝执行清除");
        }
        PurgeResult result = retention.enforceNow();
        LOG.info(() -> "[RETENTION] 策略=" + result.policy() + " 清除=" + result.purgedSequences()
                + " 法律保留=" + result.retainedByLegalHold()
                + " 未到期数量=" + result.retainedNotExpired().size());
        return result;
    }

    /** 合规清除：预演（dryRun=true）不改留存；执行结果可解释、按 requestId 幂等。 */
    public CompliancePurgeResult compliancePurge(CompliancePurgeRequest request) {
        if (ledger.isClosed()) {
            throw new TamperException(ledger.firstTamperedSequence(),
                    "账本已因破坏关闭，最早受影响序号=" + ledger.firstTamperedSequence() + "，拒绝合规清除");
        }
        return compliance.submit(request);
    }

    /** 全量完整性核验（结论 -1 表示健康）；账本已判破坏时直接回放持久结论，不重新洗白。 */
    public long verifyLedger() {
        if (ledger.isClosed()) {
            LOG.warning(() -> "[VERIFY] 账本处于破坏状态，firstTamperedSequence="
                    + ledger.firstTamperedSequence() + "，核验结论保持破坏");
            return ledger.firstTamperedSequence();
        }
        long first = ledger.verify();
        LOG.info(() -> "[VERIFY] 全量核验结论 firstTamperedSequence=" + first
                + (first < 0 ? "（账本完整）" : "（检测到破坏）"));
        return first;
    }

    /** 分段完整性核验（内存视图，有界扫描）。破坏点在区间外时区间仍可健康，破坏点在区间内必报。 */
    public VerifyResult verifyRange(long fromSeqInclusive, long toSeqInclusive) {
        if (ledger.isClosed()
                && ledger.firstTamperedSequence() >= fromSeqInclusive
                && ledger.firstTamperedSequence() <= toSeqInclusive) {
            VerifyResult r = VerifyResult.tampered(fromSeqInclusive, toSeqInclusive,
                    ledger.firstTamperedSequence(), -1, -1L,
                    "账本处于破坏状态，最早受影响序号落在本区间");
            LOG.warning(() -> "[VERIFY] 分段核验[" + fromSeqInclusive + "," + toSeqInclusive
                    + "] 命中已知破坏点=" + ledger.firstTamperedSequence());
            return r;
        }
        VerifyResult r = ledger.verifyRangeData(fromSeqInclusive, toSeqInclusive);
        LOG.info(() -> "[VERIFY] 分段核验[" + fromSeqInclusive + "," + toSeqInclusive
                + "] healthy=" + r.healthy() + " first=" + r.firstTamperedSequence()
                + " anchoredAfter=" + r.anchoredAfterDataSeq());
        return r;
    }

    public LegalHold addLegalHold(String holdId, String subjectPattern, String reason) {
        LegalHold h = holds.addHold(holdId, subjectPattern, reason);
        LOG.info(() -> "[HOLD] 新增法律保留 holdId=" + holdId + " pattern=" + subjectPattern);
        return h;
    }

    public boolean removeLegalHold(String holdId) {
        boolean removed = holds.removeHold(holdId);
        LOG.info(() -> "[HOLD] 移除法律保留 holdId=" + holdId + " 结果=" + removed);
        return removed;
    }

    public AppendOnlyLedger ledger() {
        return ledger;
    }

    public OutboxStore outbox() {
        return outbox;
    }

    public RetentionService retentionService() {
        return retention;
    }

    public CompliancePurgeService complianceService() {
        return compliance;
    }

    public LegalHoldService legalHolds() {
        return holds;
    }

    public RetryDispatcher dispatcher() {
        return dispatcher;
    }

    /**
     * 修复“账本已追加但 outbox 未登记”的跨存储缝隙（崩溃发生在两步之间）。
     * 按需懒读取明文，不在启动时把大账本全部解密一遍。
     */
    private void repairOutbox() {
        synchronized (ledger) {
            if (ledger.isClosed()) {
                // 破坏降级模式：不再触碰任何载荷（可能命中已删/损坏的 DEK），保持只读在线
                LOG.severe(() -> "[RECOVERY] 账本已关闭(最早受影响序号=" + ledger.firstTamperedSequence()
                        + ")，跳过 outbox 修复，服务以只读降级模式运行");
                return;
            }
            for (long seq = 1L, n = ledger.count(); seq <= n; seq++) {
                String payload = ledger.payloadAt(seq);
                if (payload == null) {
                    continue; // 已清除记录无载荷可转发
                }
                StoredEvent e = ledger.at(seq).orElse(null);
                if (e == null) {
                    continue;
                }
                if (outbox.find(seq).isEmpty()) {
                    outbox.register(seq, e.idempotencyKey(), payload);
                    long registeredSeq = seq;
                    LOG.info(() -> "[RECOVERY] 补登记 outbox ledgerSeq=" + registeredSeq);
                }
            }
        }
    }

    private String canonicalPayload(NormalizedEvent e) {
        try {
            ObjectNode root = mapper.createObjectNode();
            root.put("source", e.source());
            root.put("eventId", e.eventId());
            root.put("eventType", e.eventType());
            root.put("occurredAtMs", e.occurredAtMs());
            root.put("severity", e.severity());
            root.put("subject", e.subject());
            root.set("extensions", e.extensions());
            return mapper.writeValueAsString(root);
        } catch (Exception ex) {
            throw new IllegalStateException("载荷序列化失败", ex);
        }
    }

    public void close() {
        if (dispatcher != null) {
            dispatcher.stop();
        }
    }
}
