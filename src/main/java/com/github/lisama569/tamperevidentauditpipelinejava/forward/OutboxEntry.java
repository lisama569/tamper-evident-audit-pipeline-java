package com.github.lisama569.tamperevidentauditpipelinejava.forward;

/**
 * 发件箱（outbox）条目：与账本同事务登记，保证转发不丢不重（接收端幂等配合下为有效一次）。
 */
public record OutboxEntry(long id, long ledgerSequence, String idempotencyKey,
                          String payloadJson, String status, int attempts,
                          long nextAttemptAtMs, long createdAtMs, String lastErrorCategory) {

    public static final String PENDING = "PENDING";
    public static final String INFLIGHT = "INFLIGHT";
    public static final String SENT = "SENT";
    public static final String DEAD = "DEAD";
}
