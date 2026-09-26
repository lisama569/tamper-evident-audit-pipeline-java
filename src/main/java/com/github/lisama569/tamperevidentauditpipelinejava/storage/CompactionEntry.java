package com.github.lisama569.tamperevidentauditpipelinejava.storage;

import java.util.List;

/**
 * 一次合规清除（物理压实）的可审计凭证。
 *
 * <p>压实后，被清除记录的字节从段文件中消失，但本次操作本身（谁、何时、
 * 依据、清除了哪些序号、压实前后的链端哈希）被永久记录在带 HMAC 的
 * compaction 日志中，使“记录为何不存在、是否经过授权清除”可解释、可举证。
 *
 * @param id            压实事件 ID
 * @param at            压实时间（ISO-8601）
 * @param mode          ERASURE / LOGICAL_TOMBSTONE
 * @param reason        清除依据（RETENTION_EXPIRED / COMPLIANCE_ERASURE_REQUEST）
 * @param requestedBy   发起人
 * @param removedSeqs   被清除序号（升序）
 * @param blockedSeqs   因法律保留被阻止的序号（升序）
 * @param prevLastSeq   压实前末端序号
 * @param prevLastHash  压实前末端哈希
 * @param newLastSeq    压实后末端序号
 * @param newLastHash   压实后末端哈希（剩余链在新边界上的链端）
 * @param signature     对上述内容的 HMAC
 */
public record CompactionEntry(
        String id,
        String at,
        String mode,
        String reason,
        String requestedBy,
        List<Long> removedSeqs,
        List<Long> blockedSeqs,
        long prevLastSeq,
        String prevLastHash,
        long newLastSeq,
        String newLastHash,
        String signature
) {
}
