package com.github.lisama569.tamperevidentauditpipelinejava.forward;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.TreeMap;
import java.util.logging.Logger;

/**
 * outbox 持久化存储（与账本同目录的 outbox.log，逐行 JSON 事件重放）。
 *
 * <p>语义：
 * <ul>
 *   <li>每个账本序号恰好登记一次（重复 register 直接返回已有条目，不产生重复转发）。</li>
 *   <li>状态机 PENDING → INFLIGHT → SENT / DEAD；INFLIGHT 可在超时后被重新认领（崩溃恢复）。</li>
 *   <li>每次状态变更 force 落盘；重启后内存态由日志重放重建，
 *       未完成的重投从“最小未完成位置”（最小未 SENT/DEAD 的条目）继续。</li>
 * </ul>
 */
public class OutboxStore {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Logger LOG = Logger.getLogger(OutboxStore.class.getName());

    private final Path file;
    private final TreeMap<Long, OutboxEntry> entries = new TreeMap<>();

    public OutboxStore(Path outboxFile) {
        this.file = outboxFile;
        try {
            Files.createDirectories(outboxFile.toAbsolutePath().getParent());
            if (!Files.exists(outboxFile)) {
                Files.createFile(outboxFile);
            }
            recover();
        } catch (IOException e) {
            throw new IllegalStateException("无法初始化 outbox: " + outboxFile, e);
        }
    }

    public synchronized OutboxEntry register(long ledgerSequence, String idempotencyKey, String payloadJson) {
        OutboxEntry existing = findBySequence(ledgerSequence);
        if (existing != null) {
            return existing; // 幂等：同一账本记录绝不登记两次
        }
        long now = System.currentTimeMillis();
        OutboxEntry e = new OutboxEntry(ledgerSequence, ledgerSequence, idempotencyKey,
                payloadJson, OutboxEntry.PENDING, 0, now, now, null);
        append(toNode(e));
        entries.put(e.id(), e);
        return e;
    }

    /**
     * 认领到期条目：状态为 PENDING 且 nextAttemptAtMs 已到；
     * 或处于 INFLIGHT 超过 inflightRecoverMs（派发进程崩溃），从最小 id 开始，保证按序重投。
     */
    public synchronized List<OutboxEntry> claimDue(int limit, long inflightRecoverMs) {
        long now = System.currentTimeMillis();
        List<OutboxEntry> claimed = new ArrayList<>();
        for (OutboxEntry e : entries.values()) {
            if (claimed.size() >= limit) {
                break;
            }
            boolean duePending = OutboxEntry.PENDING.equals(e.status()) && e.nextAttemptAtMs() <= now;
            boolean stuckInflight = OutboxEntry.INFLIGHT.equals(e.status())
                    && now - e.nextAttemptAtMs() >= inflightRecoverMs;
            if (duePending || stuckInflight) {
                // PENDING→INFLIGHT 计一次尝试；回收卡死 INFLIGHT 不重复计数
                int attempts = e.attempts() + (duePending ? 1 : 0);
                OutboxEntry updated = new OutboxEntry(e.id(), e.ledgerSequence(), e.idempotencyKey(),
                        e.payloadJson(), OutboxEntry.INFLIGHT, attempts, now, e.createdAtMs(),
                        e.lastErrorCategory());
                append(toNode(updated));
                entries.put(e.id(), updated);
                claimed.add(updated);
            }
        }
        return claimed;
    }

    public synchronized void markSent(long id) {
        OutboxEntry e = require(id);
        OutboxEntry updated = new OutboxEntry(e.id(), e.ledgerSequence(), e.idempotencyKey(),
                e.payloadJson(), OutboxEntry.SENT, e.attempts(), System.currentTimeMillis(),
                e.createdAtMs(), e.lastErrorCategory());
        append(toNode(updated));
        entries.put(id, updated);
    }

    public synchronized void markRetry(long id, long nextAttemptAtMs, String errorCategory) {
        OutboxEntry e = require(id);
        OutboxEntry updated = new OutboxEntry(e.id(), e.ledgerSequence(), e.idempotencyKey(),
                e.payloadJson(), OutboxEntry.PENDING, e.attempts(), nextAttemptAtMs,
                e.createdAtMs(), errorCategory);
        append(toNode(updated));
        entries.put(id, updated);
    }

    public synchronized void markDead(long id, String errorCategory) {
        OutboxEntry e = require(id);
        OutboxEntry updated = new OutboxEntry(e.id(), e.ledgerSequence(), e.idempotencyKey(),
                e.payloadJson(), OutboxEntry.DEAD, e.attempts(), System.currentTimeMillis(),
                e.createdAtMs(), errorCategory);
        append(toNode(updated));
        entries.put(id, updated);
    }

    /** 把条目标记为 INFLIGHT 并把认领时刻拨到指定值（测试/崩溃恢复构造用）。 */
    public synchronized void markInflightSince(long id, long sinceMs) {
        OutboxEntry e = require(id);
        OutboxEntry updated = new OutboxEntry(e.id(), e.ledgerSequence(), e.idempotencyKey(),
                e.payloadJson(), OutboxEntry.INFLIGHT, Math.max(1, e.attempts()), sinceMs,
                e.createdAtMs(), e.lastErrorCategory());
        append(toNode(updated));
        entries.put(id, updated);
    }

    public synchronized Optional<OutboxEntry> find(long id) {
        return Optional.ofNullable(entries.get(id));
    }

    public synchronized List<OutboxEntry> all() {
        return new ArrayList<>(entries.values());
    }

    /** 重启后用于说明重投从哪里继续：最小的未完成（非 SENT/DEAD）条目 id，无则 -1。 */
    public synchronized long resumePosition() {
        return entries.values().stream()
                .filter(e -> OutboxEntry.PENDING.equals(e.status()) || OutboxEntry.INFLIGHT.equals(e.status()))
                .mapToLong(OutboxEntry::id)
                .min().orElse(-1L);
    }

    // ------------------------------------------------------------ internals

    private OutboxEntry findBySequence(long seq) {
        for (OutboxEntry e : entries.values()) {
            if (e.ledgerSequence() == seq) {
                return e;
            }
        }
        return null;
    }

    private OutboxEntry require(long id) {
        OutboxEntry e = entries.get(id);
        if (e == null) {
            throw new IllegalArgumentException("outbox 条目不存在: " + id);
        }
        return e;
    }

    private void append(ObjectNode node) {
        byte[] bytes = (node.toString() + "\n").getBytes(StandardCharsets.UTF_8);
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            ch.write(ByteBuffer.wrap(bytes));
            ch.force(true);
        } catch (IOException ex) {
            throw new IllegalStateException("outbox 写入失败", ex);
        }
    }

    private void recover() throws IOException {
        long truncatedBytes = truncateLastPartialLine();
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        for (String line : lines) {
            if (line.isBlank()) {
                continue;
            }
            try {
                OutboxEntry e = fromNode((ObjectNode) MAPPER.readTree(line));
                entries.put(e.id(), e); // 后写的状态覆盖先写的
            } catch (Exception parseError) {
                throw new IOException("outbox 日志损坏: " + line, parseError);
            }
        }
        if (truncatedBytes > 0) {
            LOG.info(() -> "outbox 打开时截断了未写完整的尾部帧 " + truncatedBytes + " 字节（崩溃半写，不可见半条）");
        }
    }

    private long truncateLastPartialLine() throws IOException {
        byte[] bytes = Files.readAllBytes(file);
        if (bytes.length == 0 || bytes[bytes.length - 1] == (byte) '\n') {
            return 0; // 空文件或最后一行完整结束
        }
        int cut = bytes.length - 1;
        while (cut > 0 && bytes[cut] != (byte) '\n') {
            cut--;
        }
        long keep = bytes[cut] == (byte) '\n' ? cut + 1L : 0L;
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE)) {
            ch.truncate(keep);
        }
        return bytes.length - keep;
    }

    private ObjectNode toNode(OutboxEntry e) {
        ObjectNode n = MAPPER.createObjectNode();
        n.put("id", e.id());
        n.put("seq", e.ledgerSequence());
        n.put("key", e.idempotencyKey());
        n.put("payload", e.payloadJson());
        n.put("status", e.status());
        n.put("attempts", e.attempts());
        n.put("next", e.nextAttemptAtMs());
        n.put("created", e.createdAtMs());
        n.put("errCat", e.lastErrorCategory());
        return n;
    }

    private OutboxEntry fromNode(ObjectNode n) {
        return new OutboxEntry(
                n.path("id").asLong(),
                n.path("seq").asLong(),
                n.path("key").asText(null),
                n.path("payload").asText(null),
                n.path("status").asText(),
                n.path("attempts").asInt(),
                n.path("next").asLong(),
                n.path("created").asLong(),
                n.hasNonNull("errCat") ? n.path("errCat").asText() : null);
    }
}
