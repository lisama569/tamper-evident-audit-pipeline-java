package com.github.lisama569.tamperevidentauditpipelinejava.forward;

import com.github.lisama569.tamperevidentauditpipelinejava.config.PipelineProperties;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.DeliveryRecord;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.DeliveryState;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.ErrorClass;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;
import com.github.lisama569.tamperevidentauditpipelinejava.storage.TamperEvidentStore;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 转发投递服务：从 outbox 顺序游标投递，保证“不丢、不产生重复转发效果、重启可续”。
 *
 * <p>语义：
 * <ul>
 *   <li><b>至少一次 + 对端幂等</b>：成功以对端 ACK + 本地 DELIVERED 落盘为准；
 *       ACK 后本地标记前崩溃会重投一次，靠 recordId 幂等去重；</li>
 *   <li><b>顺序游标</b>：最靠前未完成记录阻塞后续，避免乱序；</li>
 *   <li><b>租约</b>：领取后置 IN_FLIGHT 并设租约；崩溃重启后租约过期即从同一序号续投；</li>
 *   <li><b>退避重试</b>：可重试错误按指数退避到 maxAttempts，之后进入死信；不可重试立即死信；</li>
 *   <li><b>死信重放</b>：显式 {@link #replay} 后从该死信序号重新进入游标。</li>
 * </ul>
 */
@Service
public class DeliveryService {

    private static final Logger log = LoggerFactory.getLogger(DeliveryService.class);
    private static final long LEASE_SECONDS = 60;

    private final OutboxStore outbox;
    private final TamperEvidentStore store;
    private final AuditForwarder forwarder;
    private final PipelineProperties props;
    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "audit-delivery");
                t.setDaemon(true);
                return t;
            });
    private final AtomicBoolean busy = new AtomicBoolean(false);

    public DeliveryService(OutboxStore outbox, TamperEvidentStore store,
                           AuditForwarder forwarder, PipelineProperties props) {
        this.outbox = outbox;
        this.store = store;
        this.forwarder = forwarder;
        this.props = props;
    }

    @PostConstruct
    void start() {
        if (props.isRetryOnStartup()) {
            long delay = Math.max(50, props.getRetryInitialBackoffMs());
            scheduler.scheduleWithFixedDelay(this::tick, delay, 200, TimeUnit.MILLISECONDS);
            log.info("投递服务已启动，启动恢复=开启，初始退避={}ms，最大重试={}",
                    props.getRetryInitialBackoffMs(), props.getRetryMaxAttempts());
        }
    }

    @PreDestroy
    void stop() {
        scheduler.shutdownNow();
    }

    /** 触发一次投递扫描（调度器与测试都可调用）。 */
    public void tick() {
        if (!busy.compareAndSet(false, true)) {
            return;
        }
        try {
            Instant now = Instant.now();
            Optional<DeliveryRecord> dueOpt = outbox.nextDue(now, LEASE_SECONDS);
            if (dueOpt.isEmpty()) {
                return;
            }
            DeliveryRecord due = dueOpt.get();
            // 退避窗口未到
            if (due.nextAttemptAt() != null && due.nextAttemptAt().isAfter(now)
                    && due.state() == DeliveryState.PENDING) {
                return;
            }
            Optional<StoredRecord> recOpt = store.get(due.seq());
            if (recOpt.isEmpty()) {
                // 记录已被物理清除但仍有 outbox 项：标记完成，避免游标永久阻塞
                outbox.markDelivered(due.seq(), now);
                return;
            }
            attempt(due.seq(), recOpt.get());
        } catch (Exception e) {
            log.error("投递扫描异常（下轮继续）", e);
        } finally {
            busy.set(false);
        }
    }

    /** 同步尝试投递一条（测试可直接调用）。 */
    public void attempt(long seq, StoredRecord rec) {
        Instant now = Instant.now();
        DeliveryRecord claimed = outbox.claim(seq, now, LEASE_SECONDS);
        ForwarderResponse resp = forwarder.forward(rec);
        if (resp.success()) {
            outbox.markDelivered(seq, Instant.now());
            log.info("【转发成功】seq={} recordId={} attempts={}", seq, rec.recordId(), claimed.attempts() + 1);
            // 立即尝试推进下一条
            scheduler.execute(this::tick);
            return;
        }
        boolean retryable = ErrorClassifier.isRetryable(
                resp.errorClass() == ErrorClass.UNKNOWN ? ErrorClass.RETRYABLE : resp.errorClass());
        int attempts = claimed.attempts() + 1;
        Instant next = retryable
                ? Instant.now().plusMillis(backoffMillis(attempts))
                : null;
        DeliveryRecord updated = outbox.markFailed(seq, retryable, resp.errorCode(),
                resp.message(), props.getRetryMaxAttempts(), Instant.now(), next);
        log.warn("【转发失败】seq={} class={} retryable={} attempts={} state={} nextAttemptAt={} msg={}",
                seq, resp.errorClass(), retryable, attempts, updated.state(), next, resp.message());
    }

    /** 指数退避：min(max, initial * 2^(attempts-1))。 */
    long backoffMillis(int attempts) {
        double factor = Math.pow(2, Math.max(0, attempts - 1));
        long backoff = (long) Math.min(props.getRetryMaxBackoffMs(),
                props.getRetryInitialBackoffMs() * factor);
        return Math.max(1, backoff);
    }

    /** 死信重放：重置后立即触发扫描。 */
    public boolean replay(long seq) {
        boolean ok = outbox.replay(seq);
        if (ok) {
            log.info("【死信重放】seq={} 已重置为 PENDING", seq);
            scheduler.execute(this::tick);
        }
        return ok;
    }

    public List<DeliveryRecord> deliverySnapshot() {
        return outbox.all();
    }
}
