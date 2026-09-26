package com.github.lisama569.tamperevidentauditpipelinejava.web;

import com.github.lisama569.tamperevidentauditpipelinejava.domain.RejectReason;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;
import com.github.lisama569.tamperevidentauditpipelinejava.ingest.IngestOutcome;

import java.util.List;

/**
 * Web 层数据传输对象（全部为不可变 record）。
 */
public final class ApiDtos {

    private ApiDtos() {
    }

    /** 单条提交结果。 */
    public record ItemResult(
            IngestOutcome outcome,
            RejectReason reason,
            String field,
            String message,
            Long seq,
            String recordId,
            String hash
    ) {
        static ItemResult from(StoredRecord r) {
            return new ItemResult(null, null, null, null, r.seq(), r.recordId(), r.hash());
        }
    }

    public record BatchResponse(List<ItemResult> results, int accepted, int duplicate,
                                int rejected, int storageSealed) {
    }

    public record HoldRequest(String holdId, String reason, String by) {
    }

    public record EraseRequest(List<Long> seqs, String requestedBy, String mode) {
    }

    public record PurgeRequest(String mode) {
    }

    public record MessageResponse(String message) {
    }
}
