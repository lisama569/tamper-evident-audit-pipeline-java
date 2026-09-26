package com.github.lisama569.tamperevidentauditpipelinejava.forward;

import com.github.lisama569.tamperevidentauditpipelinejava.domain.ErrorClass;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.http.HttpTimeoutException;

/**
 * 转发失败分类：把异常 / HTTP 状态码映射为可重试或不可重试。
 *
 * <p>判定依据明确：
 * <ul>
 *   <li>连接拒绝、连接超时、读取超时、IO 错误 → RETRYABLE（对端可能暂时不可用）；</li>
 *   <li>HTTP 429（限流）、5xx（服务端错误）→ RETRYABLE；</li>
 *   <li>HTTP 408（请求超时）→ RETRYABLE；</li>
 *   <li>其余 4xx → NON_RETRYABLE（请求本身有问题，重试不会改变结果）；</li>
 *   <li>2xx/3xx → 成功；</li>
 *   <li>无法识别的异常 → 保守按 RETRYABLE（宁可多投，不可丢失）。</li>
 * </ul>
 */
public final class ErrorClassifier {

    private ErrorClassifier() {
    }

    public static ErrorClass classifyThrowable(Throwable t) {
        if (t instanceof ConnectException
                || t instanceof SocketTimeoutException
                || t instanceof HttpTimeoutException
                || t instanceof IOException) {
            return ErrorClass.RETRYABLE;
        }
        return ErrorClass.UNKNOWN;
    }

    /**
     * @return null 表示成功；否则为失败类别
     */
    public static ErrorClass classifyStatus(int status) {
        if (status >= 200 && status < 400) {
            return null;
        }
        if (status == 429 || status == 408 || status >= 500) {
            return ErrorClass.RETRYABLE;
        }
        if (status >= 400 && status < 500) {
            return ErrorClass.NON_RETRYABLE;
        }
        return ErrorClass.RETRYABLE;
    }

    public static boolean isRetryable(ErrorClass c) {
        return c != ErrorClass.NON_RETRYABLE;
    }
}
