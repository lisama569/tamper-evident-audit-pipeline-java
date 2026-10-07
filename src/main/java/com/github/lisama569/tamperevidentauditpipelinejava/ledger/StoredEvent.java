package com.github.lisama569.tamperevidentauditpipelinejava.ledger;

import com.github.lisama569.tamperevidentauditpipelinejava.retention.PurgeSource;

/**
 * 已留存的一条审计记录（DATA 条目）。
 *
 * <p>purged=true 时载荷已被合规/到期清除（加密擦除），payloadJson 为 null，
 * 但 envelope（序号、幂等键、哈希、时间、事件时间、清除来源/请求/原因）
 * 与哈希链仍完整可验证：原始内容不可恢复，但“这段历史存在过、何时因何被谁清除”仍可审计。
 *
 * @param sequence        数据序号（无空洞）
 * @param idempotencyKey  稳定幂等键
 * @param payloadJson     明文载荷；清除后为 null（懒解密时也可能为 null，见 loadPayload）
 * @param hash            本帧 HMAC
 * @param prevHash        前一帧 HMAC
 * @param storedAtMs      写入账本时间
 * @param eventTimeMs     事件 occurredAt（保留策略与合规范围判断基准）
 * @param purged          是否已加密擦除
 * @param purgeSource     清除来源（EXPIRY/COMPLIANCE）；未清除为 null
 * @param purgeRequestId  合规清除请求标识；到期清除/未清除为 null
 * @param purgeReason     清除原因（合规请求 reason 或 RETENTION）；未清除为 null
 * @param purgedAtMs      清除时间；未清除为 -1
 */
public record StoredEvent(long sequence, String idempotencyKey, String payloadJson,
                          String hash, String prevHash, long storedAtMs, long eventTimeMs,
                          boolean purged, PurgeSource purgeSource, String purgeRequestId,
                          String purgeReason, long purgedAtMs) {

    /** 追加新记录时的构造（未清除）。 */
    public static StoredEvent fresh(long sequence, String idempotencyKey, String payloadJson,
                                    String hash, String prevHash, long storedAtMs, long eventTimeMs) {
        return new StoredEvent(sequence, idempotencyKey, payloadJson, hash, prevHash,
                storedAtMs, eventTimeMs, false, null, null, null, -1L);
    }

    /** 重放 DATA 帧时（尚未应用 PURGE 标记）的构造。 */
    public static StoredEvent replayed(long sequence, String idempotencyKey, String payloadJson,
                                       String hash, String prevHash, long storedAtMs, long eventTimeMs) {
        return new StoredEvent(sequence, idempotencyKey, payloadJson, hash, prevHash,
                storedAtMs, eventTimeMs, false, null, null, null, -1L);
    }

    /** 返回清除后的不可变副本（envelope 保留，payloadJson 置 null）。 */
    public StoredEvent asPurged(PurgeSource source, String requestId, String reason, long purgedAtMs) {
        return new StoredEvent(sequence, idempotencyKey, null, hash, prevHash, storedAtMs,
                eventTimeMs, true, source, requestId, reason, purgedAtMs);
    }
}
