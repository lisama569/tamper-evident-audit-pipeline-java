package com.github.lisama569.tamperevidentauditpipelinejava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 审计流水线全部可配置项（前缀 audit.*）。
 */
@ConfigurationProperties(prefix = "audit")
public class PipelineProperties {

    /** 本地留存根目录（每段、清单、outbox 均存放在该目录）。 */
    private String storageDir = "data/audit";

    /** 哈希链记录鉴权密钥（HMAC-SHA256）；留空时使用固定本地开发默认值。 */
    private String hmacSecret = "local-dev-hmac-secret-change-me";

    /** 允许的事件时间相对未来偏移（秒），超过判定为时间异常。 */
    private long maxFutureClockSkewSeconds = 300;

    /** 允许的最早事件时间（epoch 秒，默认 0 即 1970-01-01T00:00:00Z）。 */
    private long minEventTimeEpochSeconds = 0L;

    /** 默认保留天数（记录未显式指定 retentionDays 时采用）。 */
    private int defaultRetentionDays = 90;

    /** 法律保留（legal hold）是否优先于保留到期（始终为 true，仅作显式配置）。 */
    private boolean legalHoldPrecedence = true;

    /** 转发目标 URL；留空则使用只记录日志的本地转发器。 */
    private String forwarderUrl = "";

    /** 转发连接超时（毫秒）。 */
    private int forwardConnectTimeoutMs = 2000;

    /** 转发读取超时（毫秒）。 */
    private int forwardReadTimeoutMs = 5000;

    /** 重试初始退避（毫秒）。 */
    private long retryInitialBackoffMs = 500;

    /** 重试最大退避（毫秒）。 */
    private long retryMaxBackoffMs = 30000;

    /** 单次转发尝试的最大重试次数（之后进入死信）。 */
    private int retryMaxAttempts = 5;

    /** 启动时是否自动恢复未完成的转发。 */
    private boolean retryOnStartup = true;

    public String getStorageDir() { return storageDir; }
    public void setStorageDir(String storageDir) { this.storageDir = storageDir; }

    public String getHmacSecret() { return hmacSecret; }
    public void setHmacSecret(String hmacSecret) { this.hmacSecret = hmacSecret; }

    public long getMaxFutureClockSkewSeconds() { return maxFutureClockSkewSeconds; }
    public void setMaxFutureClockSkewSeconds(long v) { this.maxFutureClockSkewSeconds = v; }

    public long getMinEventTimeEpochSeconds() { return minEventTimeEpochSeconds; }
    public void setMinEventTimeEpochSeconds(long v) { this.minEventTimeEpochSeconds = v; }

    public int getDefaultRetentionDays() { return defaultRetentionDays; }
    public void setDefaultRetentionDays(int v) { this.defaultRetentionDays = v; }

    public boolean isLegalHoldPrecedence() { return legalHoldPrecedence; }
    public void setLegalHoldPrecedence(boolean v) { this.legalHoldPrecedence = v; }

    public String getForwarderUrl() { return forwarderUrl; }
    public void setForwarderUrl(String forwarderUrl) { this.forwarderUrl = forwarderUrl; }

    public int getForwardConnectTimeoutMs() { return forwardConnectTimeoutMs; }
    public void setForwardConnectTimeoutMs(int v) { this.forwardConnectTimeoutMs = v; }

    public int getForwardReadTimeoutMs() { return forwardReadTimeoutMs; }
    public void setForwardReadTimeoutMs(int v) { this.forwardReadTimeoutMs = v; }

    public long getRetryInitialBackoffMs() { return retryInitialBackoffMs; }
    public void setRetryInitialBackoffMs(long v) { this.retryInitialBackoffMs = v; }

    public long getRetryMaxBackoffMs() { return retryMaxBackoffMs; }
    public void setRetryMaxBackoffMs(long v) { this.retryMaxBackoffMs = v; }

    public int getRetryMaxAttempts() { return retryMaxAttempts; }
    public void setRetryMaxAttempts(int v) { this.retryMaxAttempts = v; }

    public boolean isRetryOnStartup() { return retryOnStartup; }
    public void setRetryOnStartup(boolean v) { this.retryOnStartup = v; }
}
