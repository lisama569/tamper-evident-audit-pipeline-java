package com.github.lisama569.tamperevidentauditpipelinejava.domain;

import java.time.Instant;

/**
 * 一条留存记录的转发投递跟踪（持久化在 outbox 中）。
 */
public record DeliveryRecord(
        long seq,
        String recordId,
        DeliveryState state,
        int attempts,
        String lastErrorClass,
        String lastErrorMessage,
        Instant lastAttemptAt,
        Instant nextAttemptAt,
        /** IN_FLIGHT 租约到期时间，过期可被其他投递者安全接管。 */
        Instant leaseExpiresAt
) {
}
