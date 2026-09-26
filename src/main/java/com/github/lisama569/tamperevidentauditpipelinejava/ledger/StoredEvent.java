package com.github.lisama569.tamperevidentauditpipelinejava.ledger;

/**
 * 已留存的一条审计记录（DATA 条目）。
 *
 * <p>purged=true 时载荷已被合规/到期清除（加密擦除），payloadJson 为 null，
 * 但 envelope（序号、幂等键、哈希、时间）与哈希链仍完整可验证。
 */
public record StoredEvent(long sequence, String idempotencyKey, String payloadJson,
                          String hash, String prevHash, long storedAtMs, boolean purged) {
}
