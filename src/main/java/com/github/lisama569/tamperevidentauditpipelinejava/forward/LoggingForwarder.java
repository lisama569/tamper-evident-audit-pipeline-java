package com.github.lisama569.tamperevidentauditpipelinejava.forward;

import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 默认本地转发器：不发送网络请求，只以结构化日志输出记录并视为成功。
 * 用于无外部 sink 的本地验证；配置 audit.forwarder-url 后切换为 HTTP 转发器。
 */
public class LoggingForwarder implements AuditForwarder {

    private static final Logger log = LoggerFactory.getLogger(LoggingForwarder.class);

    @Override
    public ForwarderResponse forward(StoredRecord record) {
        log.info("【转发-本地sink】seq={} recordId={} source={} type={} occurredAt={}",
                record.seq(), record.recordId(),
                record.event().source(), record.event().eventType(),
                record.event().occurredAt());
        return ForwarderResponse.ok();
    }
}
