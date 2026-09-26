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

    public LegalHoldService legalHolds() {
        return holds;
    }

    public RetryDispatcher dispatcher() {
        return dispatcher;
    }

    /**
     * 修复“账本已追加但 outbox 未登记”的跨存储缝隙（崩溃发生在两步之间）。
     * 对账本中每条 DATA 记录确保 outbox 恰好有一个对应条目。
     */
    private void repairOutbox() {
        synchronized (ledger) {
            for (StoredEvent e : ledger.all()) {
                if (e.payloadJson() == null) {
                    continue; // 已清除记录无载荷可转发；其 outbox 若未发送将永远留 PENDING，见下
                }
                if (outbox.find(e.sequence()).isEmpty()) {
                    outbox.register(e.sequence(), e.idempotencyKey(), e.payloadJson());
                    LOG.info(() -> "[RECOVERY] 补登记 outbox ledgerSeq=" + e.sequence());
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
