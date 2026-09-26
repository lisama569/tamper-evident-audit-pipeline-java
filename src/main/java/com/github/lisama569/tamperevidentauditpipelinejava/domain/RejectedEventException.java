package com.github.lisama569.tamperevidentauditpipelinejava.domain;

/**
 * 归一化拒绝异常：携带稳定原因码与出错字段，绝不静默丢弃。
 */
public class RejectedEventException extends RuntimeException {

    private final RejectReason reason;
    private final String field;

    public RejectedEventException(RejectReason reason, String field, String message) {
        super(message);
        this.reason = reason;
        this.field = field;
    }

    public RejectReason getReason() { return reason; }

    public String getField() { return field; }
}
