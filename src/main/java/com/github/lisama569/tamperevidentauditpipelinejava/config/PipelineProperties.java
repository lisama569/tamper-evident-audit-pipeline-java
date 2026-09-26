package com.github.lisama569.tamperevidentauditpipelinejava.config;

import java.nio.file.Path;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 流水线配置项，前缀 audit.*。
 */
@ConfigurationProperties(prefix = "audit")
public class PipelineProperties {

    private Path storageDir = Path.of("data", "audit");
    private long maxFutureSkewMs = 60_000L;
    private int retentionDays = 90;
    private boolean autoForward = true;
    private String forwardUrl = "";
    private int forwardTimeoutMs = 5_000;
    private int retryMaxAttempts = 10;
    private long retryInitialDelayMs = 200L;
    private long retryMaxDelayMs = 30_000L;
    private long dispatchIntervalMs = 500L;
    private long inflightRecoverMs = 30_000L;

    public Path getStorageDir() { return storageDir; }
    public void setStorageDir(Path storageDir) { this.storageDir = storageDir; }
    public long getMaxFutureSkewMs() { return maxFutureSkewMs; }
    public void setMaxFutureSkewMs(long v) { this.maxFutureSkewMs = v; }
    public int getRetentionDays() { return retentionDays; }
    public void setRetentionDays(int v) { this.retentionDays = v; }
    public boolean isAutoForward() { return autoForward; }
    public void setAutoForward(boolean v) { this.autoForward = v; }
    public String getForwardUrl() { return forwardUrl; }
    public void setForwardUrl(String forwardUrl) { this.forwardUrl = forwardUrl; }
    public int getForwardTimeoutMs() { return forwardTimeoutMs; }
    public void setForwardTimeoutMs(int v) { this.forwardTimeoutMs = v; }
    public int getRetryMaxAttempts() { return retryMaxAttempts; }
    public void setRetryMaxAttempts(int v) { this.retryMaxAttempts = v; }
    public long getRetryInitialDelayMs() { return retryInitialDelayMs; }
    public void setRetryInitialDelayMs(long v) { this.retryInitialDelayMs = v; }
    public long getRetryMaxDelayMs() { return retryMaxDelayMs; }
    public void setRetryMaxDelayMs(long v) { this.retryMaxDelayMs = v; }
    public long getDispatchIntervalMs() { return dispatchIntervalMs; }
    public void setDispatchIntervalMs(long v) { this.dispatchIntervalMs = v; }
    public long getInflightRecoverMs() { return inflightRecoverMs; }
    public void setInflightRecoverMs(long v) { this.inflightRecoverMs = v; }
}
