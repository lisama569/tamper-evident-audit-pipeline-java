package com.github.lisama569.tamperevidentauditpipelinejava.forward;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.DeliveryRecord;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.DeliveryState;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 转发 outbox：每条已留存记录对应一条投递状态。
 *
 * <p>持久化采用 {@code outbox.json} 状态表（写临时文件 + fsync + 原子替换）。
 * 状态推进在锁内完成并在每次变化后立即落盘，因此进程崩溃/重启后：
 * <ul>
 *   <li>{@code PENDING} 从最小序号继续；</li>
 *   <li>{@code IN_FLIGHT} 以 {@code leaseExpiresAt} 判定租约，过期即当作未完成、从原序号继续；</li>
 *   <li>{@code DELIVERED} 永不重复投递；</li>
 *   <li>{@code DEAD_LETTER} 保留待人工/显式重放。</li>
 * </ul>
 * 顺序由序号游标保证：未确认项阻塞后续，避免乱序重投造成下游困惑。
 */
@Component
public class OutboxStore {

    private static final Logger log = LoggerFactory.getLogger(OutboxStore.class);

    private final Path file;
    private final Path tmp;
    private final ObjectMapper mapper;
    private final ReentrantLock lock = new ReentrantLock();
    private final TreeMap<Long, DeliveryRecord> table = new TreeMap<>();

    public OutboxStore(Path storageDir, ObjectMapper mapper) {
        this.file = storageDir.resolve("outbox.json");
        this.tmp = storageDir.resolve("outbox.json.tmp");
        this.mapper = mapper;
    }

    /** 启动加载（文件不存在则初始化为空）。 */
    public void initialize() throws IOException {
        lock.lock();
        try {
            Files.createDirectories(file.getParent());
            if (!Files.exists(file)) {
                persistLocked();
                return;
            }
            Snapshot snap = mapper.readValue(Files.readString(file), Snapshot.class);
            if (snap.records() != null) {
                for (DeliveryRecord r : snap.records()) {
                    table.put(r.seq(), r);
                }
            }
        } finally {
            lock.unlock();
        }
    }

    /** 登记一条新留存记录（初始 PENDING）。重复登记幂等。 */
    public void register(StoredRecord rec) {
        lock.lock();
        try {
            table.computeIfAbsent(rec.seq(), seq -> new DeliveryRecord(
                    seq, rec.recordId(), DeliveryState.PENDING, 0, null, null, null, null, null));
            persistLocked();
        } finally {
            lock.unlock();
        }
    }

    /** 游标视角：最靠前的未完成记录（PENDING，或租约已过期的 IN_FLIGHT）。 */
    public Optional<DeliveryRecord> nextDue(Instant now, long leaseSeconds) {
        lock.lock();
        try {
            for (DeliveryRecord r : table.values()) {
                if (r.state() == DeliveryState.PENDING) {
                    return Optional.of(r);
                }
                if (r.state() == DeliveryState.IN_FLIGHT
                        && (r.leaseExpiresAt() == null || !r.leaseExpiresAt().isAfter(now))) {
                    return Optional.of(r);
                }
            }
            return Optional.empty();
        } finally {
            lock.unlock();
        }
    }

    /** 领取投递权：置 IN_FLIGHT 并设置租约。 */
    public DeliveryRecord claim(long seq, Instant now, long leaseSeconds) {
        lock.lock();
        try {
            DeliveryRecord r = table.get(seq);
            DeliveryRecord updated = new DeliveryRecord(seq, r.recordId(), DeliveryState.IN_FLIGHT,
                    r.attempts(), r.lastErrorClass(), r.lastErrorMessage(),
                    now, r.nextAttemptAt(), now.plusSeconds(leaseSeconds));
            table.put(seq, updated);
            persistLocked();
            return updated;
        } finally {
            lock.unlock();
        }
    }

    /** 标记成功（终态）。 */
    public void markDelivered(long seq, Instant now) {
        lock.lock();
        try {
            DeliveryRecord r = table.get(seq);
            table.put(seq, new DeliveryRecord(seq, r.recordId(), DeliveryState.DELIVERED,
                    r.attempts(), null, null, now, null, null));
            persistLocked();
        } finally {
            lock.unlock();
        }
    }

    /**
     * 记录一次失败。
     *
     * @param retryable 是否可重试
     * @param maxAttempts 最大尝试次数（达到即 DEAD_LETTER）
     * @param now 当前时间
     * @param nextAttemptAt 下次可投递时间（退避后）
     */
    public DeliveryRecord markFailed(long seq, boolean retryable, String errorClass,
                                     String message, int maxAttempts,
                                     Instant now, Instant nextAttemptAt) {
        lock.lock();
        try {
            DeliveryRecord r = table.get(seq);
            int attempts = r.attempts() + 1;
            DeliveryState state;
            Instant next;
            if (!retryable || attempts >= maxAttempts) {
                state = DeliveryState.DEAD_LETTER;
                next = null;
                log.error("记录 seq={} 进入死信 attempts={} class={} msg={}", seq, attempts, errorClass, message);
            } else {
                state = DeliveryState.PENDING;
                next = nextAttemptAt;
            }
            DeliveryRecord updated = new DeliveryRecord(seq, r.recordId(), state, attempts,
                    errorClass, message, now, next, null);
            table.put(seq, updated);
            persistLocked();
            return updated;
        } finally {
            lock.unlock();
        }
    }

    /** 把死信记录重置为 PENDING（人工/显式重放）。 */
    public boolean replay(long seq) {
        lock.lock();
        try {
            DeliveryRecord r = table.get(seq);
            if (r == null || r.state() != DeliveryState.DEAD_LETTER) {
                return false;
            }
            table.put(seq, new DeliveryRecord(seq, r.recordId(), DeliveryState.PENDING, 0,
                    null, null, null, null, null));
            persistLocked();
            return true;
        } finally {
            lock.unlock();
        }
    }

    public Optional<DeliveryRecord> get(long seq) {
        lock.lock();
        try {
            return Optional.ofNullable(table.get(seq));
        } finally {
            lock.unlock();
        }
    }

    public List<DeliveryRecord> all() {
        lock.lock();
        try {
            return new ArrayList<>(table.values());
        } finally {
            lock.unlock();
        }
    }

    private void persistLocked() {
        try {
            Snapshot snap = new Snapshot(1, new ArrayList<>(table.values()));
            String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(snap);
            Files.write(tmp, json.getBytes(StandardCharsets.UTF_8));
            try (FileChannel ch = FileChannel.open(tmp, java.nio.file.StandardOpenOption.WRITE)) {
                ch.force(true);
            }
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new IllegalStateException("outbox 状态持久化失败", e);
        }
    }

    record Snapshot(int version, List<DeliveryRecord> records) {
    }
}
