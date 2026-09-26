package com.github.lisama569.tamperevidentauditpipelinejava.domain;

import java.time.Instant;
import java.util.Map;

/**
 * 归一化后的审计事件（不可变）。
 *
 * <p>字段语义：
 * <ul>
 *   <li>{@code idempotencyKey} 必填非空：稳定幂等键，重复提交按它去重；</li>
 *   <li>{@code source}/{@code eventType}/{@code occurredAt} 必填；</li>
 *   <li>{@code actorId}/{@code subject} 可选，缺失归一为 {@code ""}（确定且向后兼容）；</li>
 *   <li>{@code retentionDays} 可选，缺失时在归一化阶段解析为配置默认值；</li>
 *   <li>{@code extensions} 承载所有未知扩展字段，原样保留、永不抹除。</li>
 * </ul>
 */
public record AuditEvent(
        String idempotencyKey,
        String source,
        String eventType,
        Instant occurredAt,
        String actorId,
        String subject,
        int retentionDays,
        Map<String, Object> extensions
) {
    public AuditEvent {
        // 防御性拷贝与不可变化：保证留存内容不可被外部线程后续修改
        extensions = extensions == null ? Map.of() : Map.copyOf(extensions);
        actorId = actorId == null ? "" : actorId;
        subject = subject == null ? "" : subject;
    }
}
