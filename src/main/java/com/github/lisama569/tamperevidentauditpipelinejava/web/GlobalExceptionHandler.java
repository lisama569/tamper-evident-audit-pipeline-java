package com.github.lisama569.tamperevidentauditpipelinejava.web;

import java.util.LinkedHashMap;
import java.util.Map;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.TamperException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 把接入层异常映射为带可区分原因的 HTTP 响应，绝不静默丢弃。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> malformed(HttpMessageNotReadableException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("accepted", false);
        body.put("duplicate", false);
        body.put("sequence", -1);
        body.put("idempotencyKey", null);
        body.put("reason", "MALFORMED_JSON");
        body.put("detail", "请求体不是合法 JSON: " + rootMessage(e));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> badArg(IllegalArgumentException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("accepted", false);
        body.put("reason", "MISSING_REQUIRED_FIELD");
        body.put("detail", e.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    @ExceptionHandler(TamperException.class)
    public ResponseEntity<Map<String, Object>> tampered(TamperException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("accepted", false);
        body.put("duplicate", false);
        body.put("sequence", -1);
        body.put("idempotencyKey", null);
        body.put("reason", "LEDGER_TAMPERED");
        body.put("firstTamperedSequence", e.getFirstTamperedSequence());
        body.put("detail", e.getMessage());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(body);
    }

    private static String rootMessage(Throwable t) {
        Throwable c = t;
        while (c.getCause() != null && c.getCause() != c) {
            c = c.getCause();
        }
        return c.getClass().getSimpleName() + ": " + c.getMessage();
    }
}
