package com.github.lisama569.tamperevidentauditpipelinejava.forward;

import com.github.lisama569.tamperevidentauditpipelinejava.domain.ErrorClass;

/**
 * 单次转发尝试结果。
 */
public record ForwarderResponse(
        boolean success,
        ErrorClass errorClass,
        String errorCode,
        String message
) {
    public static ForwarderResponse ok() {
        return new ForwarderResponse(true, null, "OK", "delivered");
    }

    public static ForwarderResponse failure(ErrorClass cls, String code, String message) {
        return new ForwarderResponse(false, cls, code, message);
    }
}
