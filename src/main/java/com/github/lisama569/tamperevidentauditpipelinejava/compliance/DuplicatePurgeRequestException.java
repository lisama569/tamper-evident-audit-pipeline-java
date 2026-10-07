package com.github.lisama569.tamperevidentauditpipelinejava.compliance;

/**
 * 同一 requestId 以不同的请求参数/预演标记重复提交：无法保证幂等结论一致，明确拒绝。
 */
public class DuplicatePurgeRequestException extends RuntimeException {
    public DuplicatePurgeRequestException(String message) {
        super(message);
    }
}
