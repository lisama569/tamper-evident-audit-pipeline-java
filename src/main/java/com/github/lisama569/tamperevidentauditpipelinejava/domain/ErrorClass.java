package com.github.lisama569.tamperevidentauditpipelinejava.domain;

/**
 * 转发失败错误分类：决定是否允许重试。
 */
public enum ErrorClass {
    /** 连接失败、超时、429、5xx 等：可安全重试。 */
    RETRYABLE,
    /** 4xx（除 429）、载荷被拒等：重试无意义，进入死信。 */
    NON_RETRYABLE,
    /** 无法判定的异常，按保守策略当作可重试。 */
    UNKNOWN
}
