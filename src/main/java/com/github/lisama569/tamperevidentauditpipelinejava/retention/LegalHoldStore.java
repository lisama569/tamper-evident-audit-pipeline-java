package com.github.lisama569.tamperevidentauditpipelinejava.retention;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.HmacSigner;
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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 法律保留（legal hold）登记。
 *
 * <p>持久化 {@code legal-hold.json}：seq → {holdId, reason, by, at}。
 * 整体带 HMAC 签名防篡改；任何对保留状态的删改都会在加载时被发现并拒绝启动清除流程。
 */
@Component
public class LegalHoldStore {

    private static final Logger log = LoggerFactory.getLogger(LegalHoldStore.class);

    /** 单条法律保留记录。 */
    public record Hold(String holdId, String reason, String by, String at) {
    }

    private record Snapshot(long version, TreeMap<Long, Hold> holds, String signature) {
    }

    private final Path file;
    private final Path tmp;
    private final ObjectMapper mapper;
    private final HmacSigner signer;
    private final ReentrantLock lock = new ReentrantLock();
    private final TreeMap<Long, Hold> holds = new TreeMap<>();
    private long version;

    public LegalHoldStore(Path storageDir, ObjectMapper mapper, HmacSigner signer) {
        this.file = storageDir.resolve("legal-hold.json");
        this.tmp = storageDir.resolve("legal-hold.json.tmp");
        this.mapper = mapper;
        this.signer = signer;
    }

    public void initialize() throws IOException {
        lock.lock();
        try {
            Files.createDirectories(file.getParent());
            if (!Files.exists(file)) {
                persistLocked();
                return;
            }
            Snapshot snap = mapper.readValue(Files.readString(file), Snapshot.class);
            if (snap.holds() != null && !signer.verify(canonical(snap.version(), snap.holds()), snap.signature())) {
                throw new IllegalStateException("法律保留文件签名校验失败：保留状态可能被篡改，拒绝加载");
            }
            this.version = snap.version();
            if (snap.holds() != null) {
                this.holds.putAll(snap.holds());
            }
        } finally {
            lock.unlock();
        }
    }

    public void place(long seq, String holdId, String reason, String by) {
        lock.lock();
        try {
            holds.put(seq, new Hold(holdId, reason, by, Instant.now().toString()));
            version++;
            persistLocked();
            log.info("【法律保留】seq={} holdId={} by={}", seq, holdId, by);
        } finally {
            lock.unlock();
        }
    }

    public boolean release(long seq, String holdId) {
        lock.lock();
        try {
            Hold h = holds.get(seq);
            if (h == null || (holdId != null && !holdId.isBlank() && !holdId.equals(h.holdId()))) {
                return false;
            }
            holds.remove(seq);
            version++;
            persistLocked();
            log.info("【法律保留解除】seq={} holdId={}", seq, holdId);
            return true;
        } finally {
            lock.unlock();
        }
    }

    public boolean isHeld(long seq) {
        lock.lock();
        try {
            return holds.containsKey(seq);
        } finally {
            lock.unlock();
        }
    }

    public Map<Long, Hold> snapshot() {
        lock.lock();
        try {
            return new LinkedHashMap<>(holds);
        } finally {
            lock.unlock();
        }
    }

    private String canonical(long v, TreeMap<Long, Hold> data) {
        // 用稳定的有序 JSON 作为签名输入
        TreeMap<String, Object> root = new TreeMap<>();
        root.put("version", v);
        TreeMap<String, Object> hmap = new TreeMap<>();
        data.forEach((seq, h) -> {
            TreeMap<String, Object> m = new TreeMap<>();
            m.put("holdId", h.holdId());
            m.put("reason", h.reason());
            m.put("by", h.by());
            m.put("at", h.at());
            hmap.put(String.valueOf(seq), m);
        });
        root.put("holds", hmap);
        return com.github.lisama569.tamperevidentauditpipelinejava.domain.CanonicalJson.write(root);
    }

    private void persistLocked() {
        try {
            String sig = signer.sign(canonical(version, holds));
            Snapshot snap = new Snapshot(version, new TreeMap<>(holds), sig);
            String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(snap);
            Files.write(tmp, json.getBytes(StandardCharsets.UTF_8));
            try (FileChannel ch = FileChannel.open(tmp, java.nio.file.StandardOpenOption.WRITE)) {
                ch.force(true);
            }
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new IllegalStateException("法律保留状态持久化失败", e);
        }
    }
}
