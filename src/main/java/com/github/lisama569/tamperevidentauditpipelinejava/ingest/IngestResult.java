package com.github.lisama569.tamperevidentauditpipelinejava.ingest;

import com.github.lisama569.tamperevidentauditpipelinejava.domain.RejectReason;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;

/**
 * 单条提交的完整结论：输入结论 + 判定依据（原因/字段）+ 最终状态（记录）。
 */
public record IngestResult(
        IngestOutcome outcome,
        RejectReason reason,
        String field,
        String message,
        StoredRecord record
) {
    public static IngestResult accepted(StoredRecord r) {
        return new IngestResult(IngestOutcome.ACCEPTED, null, null, "已留存", r);
    }

    public static IngestResult duplicate(StoredRecord r) {
        return new IngestResult(IngestOutcome.DUPLICATE, null, null,
                "重复提交：幂等键 " + r.event().idempotencyKey() + " 已存在，返回首次留存记录", r);
    }

    public static IngestResult rejected(RejectReason reason, String field, String message) {
        return new IngestResult(IngestOutcome.REJECTED, reason, field, message, null);
    }

    public static IngestResult storageSealed(String message) {
        return new IngestResult(IngestOutcome.STORAGE_SEALED, null, null, message, null);
    }
}
