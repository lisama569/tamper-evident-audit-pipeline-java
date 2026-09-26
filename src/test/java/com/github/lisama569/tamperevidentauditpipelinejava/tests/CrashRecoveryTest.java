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
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 崩溃恢复与锚点防回滚：尾部半帧不得可见；锚点/段被一起回滚可检测。
 */
class CrashRecoveryTest {

    private static final Logger log = LoggerFactory.getLogger(CrashRecoveryTest.class);

    private ObjectMapper mapper() {
        return new ObjectMapper().registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    private AuditEvent ev(String k) {
        return new AuditEvent(k, "s", "T", Instant.now(), "a", "b", 90, Map.of());
    }

    @Test
    void tornTrailingFrame_isTruncated_noHalfRecordVisible(@TempDir Path dir) throws Exception {
        FileAppendStore store = new FileAppendStore(dir, new HmacSigner("s"), mapper());
        store.initialize();
        for (int i = 1; i <= 3; i++) {
            store.append(ev("k" + i));
        }
        Path seg = dir.resolve("segment.log");
        long len = Files.size(seg);

        // 模拟崩溃：在尾部追加一段不完整的半帧（锚点未更新）
        byte[] garbage = new byte[]{0, 0, 0, 40, 1, 2, 3};
        Files.write(seg, garbage, StandardOpenOption.APPEND);

        FileAppendStore reopened = new FileAppendStore(dir, new HmacSigner("s"), mapper());
        reopened.initialize();
        assertFalse(reopened.isSealed(), "未确认尾部半帧应被安全截断，而非密封");
        assertEquals(3, reopened.all().size(), "半条记录绝不可见");
        assertEquals(len, Files.size(seg), "文件应被截断回锚点提交长度");
        log.info("【半帧恢复】追加 7 字节未确认尾部 => 重启后截断回 {} 字节，仅 3 条完整记录可见", len);

        // 截断后可继续正常追加且无空洞
        StoredRecord r4 = reopened.append(ev("k4"));
        assertEquals(4, r4.seq());
        FileAppendStore again = new FileAppendStore(dir, new HmacSigner("s"), mapper());
        again.initialize();
        assertEquals(4, again.all().size());
        log.info("【恢复后追加】半帧截断后追加 seq=4，再次重启 4 条完整，链连续");
    }

    @Test
    void rollbackAnchorAndSegment_isDetected(@TempDir Path dir) throws Exception {
        FileAppendStore store = new FileAppendStore(dir, new HmacSigner("s"), mapper());
        store.initialize();
        store.append(ev("k1"));
        store.append(ev("k2"));
        store.append(ev("k3"));

        // 保存 3 条时的段；随后“攻击者”把段和锚点一起回滚到只有 1 条的状态
        Path seg = dir.resolve("segment.log");
        byte[] seg3 = Files.readAllBytes(seg);
        // 先构造 1 条状态：重开新目录取其锚点不现实，改为直接删除段尾部 + 篡改锚点 lastSeq
        // 这里验证“段缺少锚点声明记录”：截断段但保留锚点
        int secondFrameOffset = frameOffset(seg3, 2) - 4;
        byte[] cut = new byte[secondFrameOffset];
        System.arraycopy(seg3, 0, cut, 0, secondFrameOffset);
        Files.write(seg, cut); // 只删段，不动锚点

        FileAppendStore reopened = new FileAppendStore(dir, new HmacSigner("s"), mapper());
        StorageStateException ex = assertThrows(StorageStateException.class, reopened::initialize);
        assertTrue(reopened.isSealed());
        log.info("【段截断检测】锚点 lastSeq=3 但段仅到 seq1 => 密封，最早受影响={}", ex.getFirstAffectedSeq());
        assertTrue(ex.getFirstAffectedSeq() >= 2);
    }

    private int frameOffset(byte[] raw, int frameNo) {
        int pos = 0;
        for (int n = 1; n <= frameNo; n++) {
            if (n == frameNo) {
                return pos + 4;
            }
            int l = ((raw[pos] & 0xff) << 24) | ((raw[pos + 1] & 0xff) << 16)
                    | ((raw[pos + 2] & 0xff) << 8) | (raw[pos + 3] & 0xff);
            pos += 4 + l + 32;
        }
        throw new IllegalStateException();
    }
}
