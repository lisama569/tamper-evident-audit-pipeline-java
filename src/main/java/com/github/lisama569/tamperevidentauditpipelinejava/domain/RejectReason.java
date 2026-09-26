package com.github.lisama569.tamperevidentauditpipelinejava.domain;

/**
 * 归一化阶段可区分的拒绝原因。每个原因对调用方稳定、可用于分类统计。
 */
public enum RejectReason {

    /** 幂等键缺失（且未通过请求头提供）。 */
    MISSING_IDEMPOTENCY_KEY,

    /** 必填字段缺失：source / eventType / occurredAt。 */
    MISSING_REQUIRED_FIELD,

    /** 字段类型不匹配（例如 source 传成数字、occurredAt 传成布尔）。 */
    TYPE_MISMATCH,

    /** 时间字段无法解析（非 ISO-8601 字符串）。 */
    MALFORMED_TIMESTAMP,

    /** 事件时间早于允许的最早时间。 */
    TIMESTAMP_TOO_OLD,

    /** 事件时间超过允许的未来时钟偏移。 */
    TIMESTAMP_IN_FUTURE,

    /** 数值型字段超出允许范围（如 retentionDays <= 0）。 */
    VALUE_OUT_OF_RANGE,

    /** 载荷不是 JSON 对象（例如传成数组或裸值）。 */
    PAYLOAD_NOT_OBJECT,

    /** 请求体不是合法 JSON。 */
    MALFORMED_JSON
}
