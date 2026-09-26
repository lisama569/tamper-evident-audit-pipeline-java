package com.github.lisama569.tamperevidentauditpipelinejava.forward;

import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;

/**
 * 审计记录转发器抽象（对端 Sink）。
 *
 * <p>实现必须保证：成功返回前对端已持久化（或幂等接收）。
 * 失败时返回明确的 {@link com.github.lisama569.tamperevidentauditpipelinejava.domain.ErrorClass}，
 * 投递器据此决定重试或进入死信。
 */
public interface AuditForwarder {

    ForwarderResponse forward(StoredRecord record);
}
