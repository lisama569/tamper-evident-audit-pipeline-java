package com.github.lisama569.tamperevidentauditpipelinejava.ingest;

import com.github.lisama569.tamperevidentauditpipelinejava.model.RejectReason;

/**
 * 归一化阶段的校验失败，携带可区分的拒绝原因。
 */
public class ValidationException extends RuntimeException {

    private final RejectReason reason;

    public ValidationException(RejectReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public RejectReason getReason() {
        return reason;
    }
}
