package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.AuditEvent;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.HmacSigner;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StorageStateException;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;
import com.github.lisama569.tamperevidentauditpipelinejava.storage.FileAppendStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 只追加留存：并发追加唯一性/无空洞、哈希链、重启恢复、篡改定位、密封拒绝。
 */
class FileAppendStoreTest {

    private static final Logger log = LoggerFactory.getLogger(FileAppendStoreTest.class);

    private final HmacSigner signer = new HmacSigner("test-secret");

    private ObjectMapper mapper() {
        ObjectMapper m = new ObjectMapper();
        m.registerModule(new JavaTimeModule());
        m.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return m;
    }

    private AuditEvent event(String key, int retentionDays) {
        return new AuditEvent(key, "src-" + key, "TYPE_A", Instant.now(),
                "actor", "subject", retentionDays,
                Map.of("ext_" + key, "v", "n", key.length()));
    }

    @Test
    void concurrentAppend_isUniqueGaplessAndChainValid(@TempDir Path dir) throws Exception {
        int threads = 16;
        int perThread = 50;
        int total = threads * perThread;
        FileAppendStore store = new FileAppendStore(dir, signer, mapper());
        store.initialize();

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<StoredRecord> all = new ConcurrentLinkedQueue<>();
        CountDownLatch done = new CountDownLatch(threads);
        for (int t = 0; t < threads; t++) {
            final int tid = t;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        String key = "t" + tid + "-" + i;
                        StoredRecord r = store.append(event(key, 90));
                        all.add(r);
                    }
                } catch (Exception e) {
                    log.error("worker error", e);
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(60, TimeUnit.SECONDS));
        pool.shutdown();

        // 唯一性
        Set<Long> seqs = new HashSet<>();
        Set<String> ids = new HashSet<>();
        for (StoredRecord r : all) {
            assertTrue(seqs.add(r.seq()), "序号重复: " + r.seq());
            assertTrue(ids.add(r.recordId()), "recordId 重复");
        }
        // 无空洞：1..total 全部出现
        assertEquals(total, seqs.size());
        for (long s = 1; s <= total; s++) {
            assertTrue(seqs.contains(s), "缺少序号 " + s);
        }
        assertEquals(total, store.lastSeq());
        log.info("【并发追加】输入={}线程x{} 判定:序号唯一且1..{}无空洞 最终lastSeq={}",
                threads, perThread, total, store.lastSeq());

        // 重启后完整恢复且哈希链可验
        FileAppendStore reopened = new FileAppendStore(dir, signer, mapper());
        reopened.initialize();
        assertFalse(reopened.isSealed());
        assertEquals(total, reopened.all().size());
        String prev = HmacSigner.GENESIS_PREV;
        for (StoredRecord r : reopened.all()) {
            assertEquals(prev, r.prevHash(), "链断裂于 " + r.seq());
            prev = r.hash();
        }
        log.info("【重启恢复】重新加载 {} 条，哈希链全部连续，存储未密封", total);
    }

    @Test
    void tamperDetected_findsEarliestSeq_andSealsRejectingAppends(@TempDir Path dir) throws Exception {
        FileAppendStore store = new FileAppendStore(dir, signer, mapper());
        store.initialize();
        for (int i = 1; i <= 5; i++) {
            store.append(event("k" + i, 90));
        }
        Path seg = dir.resolve("segment.log");
        byte[] raw = Files.readAllBytes(seg);

        // 篡改第 3 条帧内的某个字节（跳过帧头与签名区以外仍落在 payload 中部）
        // 帧结构: [4 len][payload][32 sig]；直接翻转一个稳定存在的偏移
        int targetOffset = locatePayloadOffset(raw, 3) + 40;
        raw[targetOffset] ^= 0x01;
        Files.write(seg, raw);
        log.info("【篡改输入】翻转第3条帧 payload 偏移 {} 的一个比特", targetOffset);

        FileAppendStore reopened = new FileAppendStore(dir, signer, mapper());
        StorageStateException ex = assertThrows(StorageStateException.class, reopened::initialize);
        assertTrue(reopened.isSealed(), "检测到篡改后必须密封");
        assertEquals(3, reopened.firstAffectedSeq(), "必须定位到最早受影响记录 seq=3，实际=" + ex.getFirstAffectedSeq());
        log.info("【篡改判定】最早受影响序号={} 原因={}", reopened.firstAffectedSeq(), reopened.sealedReason());

        // 密封后新追加必须被明确拒绝
        StorageStateException refused = assertThrows(StorageStateException.class,
                () -> reopened.append(event("new", 90)));
        assertTrue(refused.getMessage().contains("密封"));
        log.info("【密封拒绝】密封后追加被拒绝: {}", refused.getMessage());
    }

    @Test
    void deleteRecordDetectedAsUnauthorizedRemoval(@TempDir Path dir) throws Exception {
        FileAppendStore store = new FileAppendStore(dir, signer, mapper());
        store.initialize();
        for (int i = 1; i <= 4; i++) {
            store.append(event("del" + i, 90));
        }
        Path seg = dir.resolve("segment.log");
        byte[] raw = Files.readAllBytes(seg);
        // 删除第二条帧的全部字节
        int start2 = locatePayloadOffset(raw, 2) - 4;
        int start3 = locatePayloadOffset(raw, 3) - 4;
        byte[] cut = new byte[raw.length - (start3 - start2)];
        System.arraycopy(raw, 0, cut, 0, start2);
        System.arraycopy(raw, start3, cut, start2, raw.length - start3);
        Files.write(seg, cut);

        FileAppendStore reopened = new FileAppendStore(dir, signer, mapper());
        StorageStateException ex = assertThrows(StorageStateException.class, reopened::initialize);
        assertTrue(reopened.isSealed());
        log.info("【删除判定】最早受影响序号={} 原因={}", ex.getFirstAffectedSeq(), reopened.sealedReason());
        assertTrue(ex.getFirstAffectedSeq() <= 3, "删除应在序号2或链断裂处被检出");
    }

    @Test
    void unknownFieldsArePreservedAndAffectHash(@TempDir Path dir) throws Exception {
        FileAppendStore store = new FileAppendStore(dir, signer, mapper());
        store.initialize();
        AuditEvent e = new AuditEvent("x1", "s", "T", Instant.now(), "a", "b", 30,
                Map.of("customField", Map.of("nested", 42), "extra", "kept"));
        StoredRecord r = store.append(e);
        FileAppendStore reopened = new FileAppendStore(dir, signer, mapper());
        reopened.initialize();
        StoredRecord back = reopened.get(1).orElseThrow();
        assertEquals("kept", back.event().extensions().get("extra"));
        assertEquals(42, ((Map<?, ?>) back.event().extensions().get("customField")).get("nested"));
        assertEquals(r.hash(), back.hash());
        log.info("【扩展保留】unknown 字段保留: {} 哈希一致={}", back.event().extensions(), r.hash().equals(back.hash()));
    }

    /** 返回第 n 条帧 payload 的起始绝对偏移（帧从 1 开始）。 */
    private int locatePayloadOffset(byte[] raw, int frameNo) {
        int pos = 0;
        for (int n = 1; n <= frameNo; n++) {
            if (n == frameNo) {
                return pos + 4;
            }
            int len = ((raw[pos] & 0xff) << 24) | ((raw[pos + 1] & 0xff) << 16)
                    | ((raw[pos + 2] & 0xff) << 8) | (raw[pos + 3] & 0xff);
            pos += 4 + len + 32;
        }
        throw new IllegalStateException("frame not found " + frameNo);
    }
}
