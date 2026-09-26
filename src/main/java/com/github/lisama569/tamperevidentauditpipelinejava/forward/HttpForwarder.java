package com.github.lisama569.tamperevidentauditpipelinejava.forward;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * 基于 JDK HttpClient 的转发器，按错误类别区分可重试与不可重试：
 *
 * <ul>
 *   <li>2xx：SUCCESS。</li>
 *   <li>408 / 429 / 5xx：RETRYABLE（服务端临时不可用、限流、请求超时）。</li>
 *   <li>4xx（除 408/429）：NON_RETRYABLE（载荷被明确拒绝，重试不会改变结论）。</li>
 *   <li>连接异常 / 读超时：RETRYABLE（NETWORK）。</li>
 *   <li>其它未预期异常：NON_RETRYABLE（UNEXPECTED），进入死信并保留可解释原因。</li>
 * </ul>
 */
public class HttpForwarder implements Forwarder {

    private final String endpointUrl;
    private final HttpClient client;
    private final int timeoutMs;

    public HttpForwarder(String endpointUrl, HttpClient client, int timeoutMs) {
        this.endpointUrl = endpointUrl;
        this.client = client;
        this.timeoutMs = timeoutMs;
    }

    @Override
    public ForwardResult forward(OutboxEntry entry) {
        if (endpointUrl == null || endpointUrl.isBlank()) {
            return ForwardResult.nonRetryable("NOT_CONFIGURED", "未配置转发地址 audit.forward-url");
        }
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(endpointUrl))
                    .timeout(Duration.ofMillis(timeoutMs))
                    .header("Content-Type", "application/json")
                    // 稳定幂等键透传：接收端据此去重，配合 at-least-once 重投实现有效一次
                    .header("Idempotency-Key", nullToEmpty(entry.idempotencyKey()))
                    .POST(HttpRequest.BodyPublishers.ofString(nullToEmpty(entry.payloadJson()),
                            StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> resp = client.send(request, HttpResponse.BodyHandlers.ofString());
            int code = resp.statusCode();
            if (code >= 200 && code < 300) {
                return ForwardResult.success();
            }
            if (code == 408 || code == 429 || code >= 500) {
                return ForwardResult.retryable("HTTP_" + code,
                        "可重试的 HTTP 状态码 " + code + ": " + abbreviate(resp.body()));
            }
            return ForwardResult.nonRetryable("HTTP_" + code,
                    "不可重试的 HTTP 状态码 " + code + ": " + abbreviate(resp.body()));
        } catch (HttpTimeoutException | SocketTimeoutException e) {
            return ForwardResult.retryable("TIMEOUT", "转发超时: " + e.getMessage());
        } catch (ConnectException e) {
            return ForwardResult.retryable("CONNECT_REFUSED", "连接被拒绝: " + e.getMessage());
        } catch (java.io.IOException e) {
            return ForwardResult.retryable("NETWORK", "网络 IO 失败: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            return ForwardResult.nonRetryable("BAD_ENDPOINT", "转发地址非法: " + e.getMessage());
        } catch (Exception e) {
            return ForwardResult.nonRetryable("UNEXPECTED",
                    e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static String abbreviate(String s) {
        if (s == null) {
            return "";
        }
        return s.length() <= 200 ? s : s.substring(0, 200) + "...";
    }
}
