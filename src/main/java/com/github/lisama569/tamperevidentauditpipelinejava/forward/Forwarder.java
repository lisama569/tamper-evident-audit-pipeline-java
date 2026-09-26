package com.github.lisama569.tamperevidentauditpipelinejava.forward;

/**
 * 出站转发器抽象：把一条记录的载荷投递到外部系统。
 */
public interface Forwarder {

    /** @return 投递结果（成功 / 可重试失败 / 不可重试失败） */
    ForwardResult forward(OutboxEntry entry);

    record ForwardResult(ForwardOutcome outcome, String errorCategory, String detail) {
        public static ForwardResult success() { return new ForwardResult(ForwardOutcome.SUCCESS, null, null); }
        public static ForwardResult retryable(String category, String detail) {
            return new ForwardResult(ForwardOutcome.RETRYABLE, category, detail);
        }
        public static ForwardResult nonRetryable(String category, String detail) {
            return new ForwardResult(ForwardOutcome.NON_RETRYABLE, category, detail);
        }
    }
}
