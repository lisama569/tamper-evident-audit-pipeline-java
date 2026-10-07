package com.github.lisama569.tamperevidentauditpipelinejava.retention;

/**
 * 清除来源：区分“保留到期清除”与“主动合规清除”。
 */
public enum PurgeSource {
    EXPIRY,     // 保留到期清除（RETENTION_EXPIRY）
    COMPLIANCE  // 主动合规清除（带请求标识与原因）
}
