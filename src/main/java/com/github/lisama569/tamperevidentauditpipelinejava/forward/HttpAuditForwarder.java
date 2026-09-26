package com.github.lisama569.tamperevidentauditpipelinejava.forward;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.ErrorClass;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.TreeMap;

/**
 * 基于 JDK HttpClient 的 HTTP 转发器。
 *
 * <p>请求携带 {@code X-Record-Id} 与 {@code X-Record-Seq}，对端应据此做幂等接收，
 * 从而配合“至少一次 + 重投”保证不产生重复的业务效果。
 */
public class HttpAuditForwarder implements AuditForwarder {

    private final URI url;
    private final HttpClient client;
    private final ObjectMapper mapper;
    private final int readTimeoutMs;

    public HttpAuditForwarder(String url, int connectTimeoutMs, int readTimeoutMs, ObjectMapper mapper) {
        this.url = URI.create(url);
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(connectTimeoutMs))
                .build();
        this.mapper = mapper;
        this.readTimeoutMs = readTimeoutMs;
    }

    @Override
    public ForwarderResponse forward(StoredRecord record) {
        try {
            TreeMap<String, Object> body = new TreeMap<>();
            body.put("seq", record.seq());
            body.put("recordId", record.recordId());
            body.put("event", mapper.convertValue(record.event(), TreeMap.class));
            HttpRequest req = HttpRequest.newBuilder(url)
                    .timeout(Duration.ofMillis(readTimeoutMs))
                    .header("Content-Type", "application/json")
                    .header("X-Record-Id", record.recordId())
                    .header("X-Record-Seq", String.valueOf(record.seq()))
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            ErrorClass cls = ErrorClassifier.classifyStatus(resp.statusCode());
            if (cls == null) {
                return ForwarderResponse.ok();
            }
            String code = cls == ErrorClass.RETRYABLE ? "HTTP_" + resp.statusCode() + "_RETRYABLE"
                    : "HTTP_" + resp.statusCode() + "_NON_RETRYABLE";
            return ForwarderResponse.failure(cls, code,
                    "HTTP " + resp.statusCode() + ": " + truncate(resp.body()));
        } catch (Exception e) {
            ErrorClass cls = ErrorClassifier.classifyThrowable(e);
            return ForwarderResponse.failure(cls, cls.name(), e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }


    private static String truncate(String s) {
        if (s == null) {
            return "";
        }
        return s.length() <= 200 ? s : s.substring(0, 200) + "...";
    }
}
