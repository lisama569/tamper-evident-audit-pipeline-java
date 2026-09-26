package com.github.lisama569.tamperevidentauditpipelinejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.AuditEvent;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.RejectedEventException;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StorageStateException;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.OutboxStore;
import com.github.lisama569.tamperevidentauditpipelinejava.storage.TamperEvidentStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 接入流水线编排：归一化 → 幂等去重 → 防篡改追加 → 登记 outbox。
 *
 * <p>并发要点：幂等占位先于追加；追加成功再绑定序号并登记 outbox；
 * 任何一步失败都释放幂等占位，使客户端可在修正后重试。
 */
@Service
public class IngestService {

    private static final Logger log = LoggerFactory.getLogger(IngestService.class);

    private final EventNormalizer normalizer;
    private final TamperEvidentStore store;
    private final IdempotencyIndex idempotency;
    private final OutboxStore outbox;

    public IngestService(EventNormalizer normalizer,
                         TamperEvidentStore store,
                         IdempotencyIndex idempotency,
                         OutboxStore outbox) {
        this.normalizer = normalizer;
        this.store = store;
        this.idempotency = idempotency;
        this.outbox = outbox;
    }

    /**
     * 等待同键占位方完成：返回已绑定记录的 DUPLICATE 结论；
     * 若占位被释放（对方失败）或超时，返回 null 由调用方重新抢占。
     */
    private IngestResult waitForBound(String key, long deadlineNanos) {
        while (System.nanoTime() < deadlineNanos) {
            var seq = idempotency.seqOf(key);
            if (seq.isPresent()) {
                return store.get(seq.get())
                        .map(IngestResult::duplicate)
                        .orElse(null);
            }
            // seqOf 为空有两种情况：仍在占位(PENDING)，或占位方失败已释放。
            // tryAcquire 会区分：若返回 Existing/Acquired 说明占位已解除。
            if (!idempotency.isPending(key)) {
                return null;
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
        return null;
    }

    public IngestResult submit(JsonNode node, String headerIdempotencyKey) {
        AuditEvent event;
        try {
            event = normalizer.normalize(node, headerIdempotencyKey);
        } catch (RejectedEventException e) {
            log.info("【接入拒绝】reason={} field={} msg={}", e.getReason(), e.getField(), e.getMessage());
            return IngestResult.rejected(e.getReason(), e.getField(), e.getMessage());
        }

        IdempotencyIndex.AcquireResult acquired = idempotency.tryAcquire(event.idempotencyKey());
        if (acquired instanceof IdempotencyIndex.AcquireResult.Existing ex) {
            StoredRecord first = store.get(ex.seq())
                    .orElseThrow(() -> new IllegalStateException("幂等索引指向不存在记录 seq=" + ex.seq()));
            log.info("【接入重复】key={} firstSeq={}", event.idempotencyKey(), ex.seq());
            return IngestResult.duplicate(first);
        }
        if (acquired instanceof IdempotencyIndex.AcquireResult.InFlight) {
            // 同键并发：占位方在临界区内完成追加并绑定序号（耗时毫秒级）。
            // 带时间预算轮询等待，避免自旋次数不足时把并发请求错误地判为失败。
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(10);
            IngestResult bound = waitForBound(event.idempotencyKey(), deadline);
            if (bound != null) {
                return bound;
            }
            // 超时仍无结果（占位方大概率异常释放了占位）：尝试重新抢占
            IdempotencyIndex.AcquireResult retry = idempotency.tryAcquire(event.idempotencyKey());
            if (retry instanceof IdempotencyIndex.AcquireResult.Existing ex2) {
                return IngestResult.duplicate(store.get(ex2.seq()).orElseThrow());
            }
            if (!(retry instanceof IdempotencyIndex.AcquireResult.Acquired)) {
                return IngestResult.rejected(com.github.lisama569.tamperevidentauditpipelinejava.domain.RejectReason.MISSING_IDEMPOTENCY_KEY,
                        "idempotencyKey", "同键并发提交状态未定，请稍后重试");
            }
        }

        try {
            StoredRecord rec = store.append(event);
            idempotency.bind(event.idempotencyKey(), rec.seq());
            outbox.register(rec);
            log.info("【接入接受】key={} seq={} hash={}", event.idempotencyKey(), rec.seq(), rec.hash());
            return IngestResult.accepted(rec);
        } catch (StorageStateException e) {
            idempotency.release(event.idempotencyKey());
            log.error("【接入拒绝-存储密封】firstAffectedSeq={} reason={}", e.getFirstAffectedSeq(), e.getMessage());
            return IngestResult.storageSealed(e.getMessage());
        } catch (RuntimeException e) {
            idempotency.release(event.idempotencyKey());
            throw e;
        }
    }
}
