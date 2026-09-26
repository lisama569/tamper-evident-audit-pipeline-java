package com.github.lisama569.tamperevidentauditpipelinejava.forward;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 重试调度器。
 *
 * <ul>
 *   <li>周期扫描 outbox，按 id 升序认领到期条目（重启后从 {@link OutboxStore#resumePosition()}
 *       即最小未完成位置继续，可预期）。</li>
 *   <li>SUCCESS → SENT（终态，绝不重复转发）；RETRYABLE → PENDING 并按指数退避安排下一次，
 *       超过最大次数 → DEAD 死信；NON_RETRYABLE → 立即 DEAD。</li>
 *   <li>认领时置 INFLIGHT 并落盘；派发进程崩溃后，INFLIGHT 超过 inflightRecoverMs 会被重新认领，
 *       重投不丢失（接收端凭 Idempotency-Key 去重，故不产生业务重复）。</li>
 * </ul>
 */
public class RetryDispatcher {

    private static final Logger LOG = Logger.getLogger(RetryDispatcher.class.getName());

    private final OutboxStore store;
    private final Forwarder forwarder;
    private final int maxAttempts;
    private final long initialDelayMs;
    private final long maxDelayMs;
    private final long dispatchIntervalMs;
    private final long inflightRecoverMs;

    private ScheduledExecutorService scheduler;
    private volatile boolean running;

    public RetryDispatcher(OutboxStore store, Forwarder forwarder, int maxAttempts,
                           long initialDelayMs, long maxDelayMs, long dispatchIntervalMs,
                           long inflightRecoverMs) {
        this.store = store;
        this.forwarder = forwarder;
        this.maxAttempts = maxAttempts;
        this.initialDelayMs = initialDelayMs;
        this.maxDelayMs = maxDelayMs;
        this.dispatchIntervalMs = dispatchIntervalMs;
        this.inflightRecoverMs = inflightRecoverMs;
    }

    public synchronized void start() {
        if (running) {
            return;
        }
        running = true;
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "audit-retry-dispatcher");
            t.setDaemon(true);
            return t;
        });
        long resume = store.resumePosition();
        LOG.info(() -> "重试调度器启动，重投继续位置(最小未完成 outbox id)=" + resume);
        scheduler.scheduleWithFixedDelay(() -> {
            try {
                dispatchOnce();
            } catch (Throwable t) {
                LOG.log(Level.WARNING, "派发轮次异常（不影响后续轮次）", t);
            }
        }, 0L, dispatchIntervalMs, TimeUnit.MILLISECONDS);
    }

    public synchronized void stop() {
        running = false;
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
    }

    /** 执行一轮认领与派发，返回本轮处理的条目数。测试可直接调用。 */
    public int dispatchOnce() {
        List<OutboxEntry> due = store.claimDue(64, inflightRecoverMs);
        for (OutboxEntry e : due) {
            Forwarder.ForwardResult result;
            try {
                result = forwarder.forward(e);
            } catch (Exception ex) {
                result = Forwarder.ForwardResult.nonRetryable("DISPATCH_EXCEPTION",
                        ex.getClass().getSimpleName() + ": " + ex.getMessage());
            }
            final Forwarder.ForwardResult outcome = result;
            switch (outcome.outcome()) {
                case SUCCESS -> {
                    store.markSent(e.id());
                    LOG.info(() -> "转发成功 outboxId=" + e.id() + " ledgerSeq=" + e.ledgerSequence()
                            + " attempts=" + e.attempts());
                }
                case NON_RETRYABLE -> {
                    store.markDead(e.id(), outcome.errorCategory());
                    LOG.warning(() -> "不可重试，进入死信 outboxId=" + e.id()
                            + " category=" + outcome.errorCategory() + " detail=" + outcome.detail());
                }
                case RETRYABLE -> {
                    if (e.attempts() >= maxAttempts) {
                        store.markDead(e.id(), outcome.errorCategory() + "(RETRIES_EXHAUSTED)");
                        LOG.warning(() -> "重试次数耗尽，进入死信 outboxId=" + e.id()
                                + " attempts=" + e.attempts() + " category=" + outcome.errorCategory());
                    } else {
                        long delay = backoffMs(e.attempts());
                        store.markRetry(e.id(), System.currentTimeMillis() + delay, outcome.errorCategory());
                        LOG.info(() -> "可重试失败 outboxId=" + e.id() + " attempt=" + e.attempts()
                                + " category=" + outcome.errorCategory() + " nextDelayMs=" + delay
                                + " detail=" + outcome.detail());
                    }
                }
            }
        }
        return due.size();
    }

    /** 指数退避：min(initial * 2^(attempt-1), max)，无随机抖动以保证测试确定性。 */
    public long backoffMs(int attempt) {
        long delay = initialDelayMs;
        for (int i = 1; i < attempt; i++) {
            if (delay >= maxDelayMs / 2) {
                return maxDelayMs;
            }
            delay *= 2;
        }
        return Math.min(delay, maxDelayMs);
    }
}
