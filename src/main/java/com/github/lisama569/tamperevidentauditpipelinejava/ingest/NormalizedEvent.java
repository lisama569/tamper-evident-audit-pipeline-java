package com.github.lisama569.tamperevidentauditpipelinejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * 归一化后的事件（确定性默认值已应用，未知扩展字段保留在 extensions 中）。
 */
public record NormalizedEvent(String source, String eventId, String eventType,
                              long occurredAtMs, String severity, String subject,
                              JsonNode extensions) {
}
