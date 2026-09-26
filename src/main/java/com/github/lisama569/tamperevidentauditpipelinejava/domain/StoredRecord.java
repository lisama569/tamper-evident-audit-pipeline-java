package com.github.lisama569.tamperevidentauditpipelinejava.domain;

import java.time.Instant;

/**
 * 已进入只追加日志的记录（不可变）。
 *
 * <p>{@code seq} 为并发下唯一且无空洞的全局序号；{@code prevHash}/{@code hash}
 * 构成防篡改哈希链，任何对历史记录的改动都会使后续链路校验失败。
 */
public record StoredRecord(
        long seq,
        String recordId,
        AuditEvent event,
        Instant appendedAt,
        String prevHash,
        String hash
) {
}
