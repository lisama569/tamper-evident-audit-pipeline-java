package com.github.lisama569.tamperevidentauditpipelinejava.model;

/**
 * 事件被拒绝（或判定为重复）时的可区分原因分类。
 */
public enum RejectReason {
    MALFORMED_JSON,
    MISSING_REQUIRED_FIELD,
    FIELD_TYPE_MISMATCH,
    INVALID_TIMESTAMP,
    SUSPICIOUS_TIMESTAMP,
    DUPLICATE_EVENT,
    LEDGER_TAMPERED,
    LEDGER_CLOSED,
    INTERNAL_ERROR
}
