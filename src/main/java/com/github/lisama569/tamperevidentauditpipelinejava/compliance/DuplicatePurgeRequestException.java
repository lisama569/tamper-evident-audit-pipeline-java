package com.github.lisama569.tamperevidentauditpipelinejava.compliance;

/**
 * 同一 requestId 携带了与首次不同的请求体：幂等键冲突，拒绝（HTTP 409）。
 */
public class DuplicatePurgeRequestException extends RuntimeException {

    private final String requestId;

    public DuplicatePurgeRequestException(String requestId, String message) {
        super(message);
        this.requestId = requestId;
    }

    public String requestId() {
        return requestId;
    }
}
