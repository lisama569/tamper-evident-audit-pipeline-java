package com.github.lisama569.tamperevidentauditpipelinejava.model;

/**
 * 一次事件接入的结论：accepted 表示新写入；duplicate 表示幂等命中；
 * 其余为拒绝，reason/detail 给出可区分的原因。
 */
public record IngestResult(boolean accepted, boolean duplicate, long sequence,
                           String idempotencyKey, RejectReason reason, String detail) {

    public static IngestResult accepted(long sequence, String idempotencyKey) {
        return new IngestResult(true, false, sequence, idempotencyKey, null, null);
    }

    public static IngestResult duplicate(long sequence, String idempotencyKey) {
        return new IngestResult(true, true, sequence, idempotencyKey, RejectReason.DUPLICATE_EVENT, null);
    }

    public static IngestResult rejected(RejectReason reason, String detail) {
        return new IngestResult(false, false, -1L, null, reason, detail);
    }
}
