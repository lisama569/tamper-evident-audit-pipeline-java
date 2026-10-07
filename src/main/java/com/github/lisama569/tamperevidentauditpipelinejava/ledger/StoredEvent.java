package com.github.lisama569.tamperevidentauditpipelinejava.ledger;

/**
 * 已留存的一条审计记录（DATA 条目）。
 *
 * <p>purged=true 时载荷已被合规/到期清除（加密擦除），payloadJson 为 null，
 * 但 envelope（序号、幂等键、哈希、时间）与哈希链仍完整可验证。
 *
 * <p>v2：重放时不再立即解密，而是携带密文 {@code bodyB64}；首次需要明文时由
 * {@link AppendOnlyLedger} 懒解密并回填。这样大账本重启恢复只做线性哈希校验，
 * 不随记录数量成倍拖慢。purged=true 或尚待懒解密时 payloadJson 均可能为 null，
 * 区分方式是 purged 标志与 bodyB64 是否存在。
 */
public record StoredEvent(long sequence, String idempotencyKey, String payloadJson,
                          String hash, String prevHash, long storedAtMs, boolean purged,
                          String bodyB64) {

    /** 写入路径使用：明文已在内存，直接携带。 */
    public StoredEvent(long sequence, String idempotencyKey, String payloadJson,
                       String hash, String prevHash, long storedAtMs, boolean purged) {
        this(sequence, idempotencyKey, payloadJson, hash, prevHash, storedAtMs, purged, null);
    }

    /** 懒解密回填明文（仅 ledger 包内部使用）；清除后回填 null。 */
    StoredEvent withPayload(String payloadJson) {
        return new StoredEvent(sequence, idempotencyKey, payloadJson, hash, prevHash,
                storedAtMs, purged, bodyB64);
    }

    /** 清除后变更 envelope 状态（链内标记 + 加密擦除）。 */
    StoredEvent asPurged() {
        return new StoredEvent(sequence, idempotencyKey, null, hash, prevHash,
                storedAtMs, true, null);
    }
}
