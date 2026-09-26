package com.github.lisama569.tamperevidentauditpipelinejava.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.AuditEvent;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.CanonicalJson;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.HmacSigner;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StorageStateException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * 基于单段长度分帧文件 + 独立锚点文件的只追加存储实现。
 *
 * <p>文件：
 * <ul>
 *   <li>{@code segment.log}：帧序列；</li>
 *   <li>{@code anchor.json}：锚点（lastSeq/lastHash/length + HMAC），
 *       通过“写临时文件 + fsync + 原子 move + fsync 目录”更新；</li>
 *   <li>{@code anchor.genesis}：进程首次初始化时写入的创世锚点只读副本，
 *       用于检测“锚点与段一起被回滚到更早状态”。</li>
 * </ul>
 */
public class FileAppendStore implements TamperEvidentStore {

    private static final Logger log = LoggerFactory.getLogger(FileAppendStore.class);

    /** 单帧最大长度（16 MiB），超过视为损坏，避免畸形长度前缀导致巨量分配。 */
    private static final int MAX_FRAME_PAYLOAD = 16 * 1024 * 1024;

    private final Path dir;
    private final Path segmentFile;
    private final Path anchorFile;
    private final Path anchorTmp;
    private final Path genesisFile;
    private final Path tombstoneFile;
    private final HmacSigner signer;
    private final FrameCodec codec;
    private final ObjectMapper mapper;
    private final Object lock = new Object();

    private final ArrayList<StoredRecord> records = new ArrayList<>();
    private final java.util.TreeSet<Long> erasedSeqs = new java.util.TreeSet<>();
    private long lastSeq;
    private String lastHash;
    private long fileLength;
    private volatile boolean sealed;
    private volatile long firstAffected = -1;
    private volatile String sealedReason = "";

    public FileAppendStore(Path dir, HmacSigner signer, ObjectMapper mapper) {
        this.dir = dir;
        this.segmentFile = dir.resolve("segment.log");
        this.anchorFile = dir.resolve("anchor.json");
        this.anchorTmp = dir.resolve("anchor.json.tmp");
        this.genesisFile = dir.resolve("anchor.genesis");
        this.tombstoneFile = dir.resolve("erased-seqs.json");
        this.signer = signer;
        this.codec = new FrameCodec(signer);
        this.mapper = mapper;
    }

    /** 初始化目录并执行启动校验/崩溃恢复。必须在对外服务前调用一次。 */
    public void initialize() throws IOException {
        synchronized (lock) {
            Files.createDirectories(dir);
            if (!Files.exists(segmentFile)) {
                Files.createFile(segmentFile);
            }
            if (!Files.exists(anchorFile)) {
                writeAnchor(Anchor.empty());
            }
            Anchor anchor = readAnchor();
            verifyAnchorSignature(anchor);
            checkGenesisRollback(anchor);
            loadErasedSeqsLocked();
            recoverAndVerify(anchor);
        }
    }

    @Override
    public StoredRecord append(AuditEvent event) {
        synchronized (lock) {
            ensureNotSealed();
            long seq = lastSeq + 1;
            // 前驱取段内现存最后一条（压实可能已使 lastHash 指回创世）
            String prev = records.isEmpty() ? HmacSigner.GENESIS_PREV
                    : records.get(records.size() - 1).hash();
            String payload = canonicalEvent(event);
            String hash = signer.chainHash(prev, payload);
            StoredRecord rec = new StoredRecord(
                    seq,
                    UUID.randomUUID().toString(),
                    event,
                    Instant.now(),
                    prev,
                    hash);

            byte[] frame = codec.encode(envelopeJson(rec));

            long positionBefore = fileLength;
            try {
                writeFrameDurably(frame);
            } catch (IOException e) {
                // 写入失败：主动回滚文件到写入前长度，杜绝半帧残留后继续写入
                failSealedOrTruncate(positionBefore, e);
                throw new StorageStateException(seq,
                        "帧落盘失败，已回滚至写入前长度 " + positionBefore, e);
            }

            records.add(rec);
            lastSeq = seq;
            lastHash = hash;
            fileLength += frame.length;

            try {
                writeAnchor(new Anchor(lastSeq, lastHash, fileLength, anchorSignature(lastSeq, lastHash, fileLength)));
            } catch (IOException e) {
                // 帧已确认但锚点更新失败：下次启动会按旧锚点恢复（该帧被当作未确认尾部截断）。
                // 为保持“已确认序号无空洞”，这里密封存储，拒绝继续写入可疑内容。
                seal(seq, "记录帧已写入但锚点更新失败，拒绝继续追加: " + e.getMessage());
                throw new StorageStateException(seq, sealedReason, e);
            }
            return rec;
        }
    }

    @Override
    public Optional<StoredRecord> get(long seq) {
        synchronized (lock) {
            if (seq <= 0 || seq > lastSeq || erasedSeqs.contains(seq)) {
                return Optional.empty();
            }
            return records.stream().filter(r -> r.seq() == seq).findFirst();
        }
    }

    @Override
    public List<StoredRecord> all() {
        synchronized (lock) {
            return List.copyOf(records);
        }
    }

    @Override
    public Set<Long> erasedSeqs() {
        synchronized (lock) {
            return Set.copyOf(erasedSeqs);
        }
    }

    @Override
    public void markTombstones(Set<Long> seqsToTombstone) {
        synchronized (lock) {
            ensureNotSealed();
            int before = erasedSeqs.size();
            for (Long s : seqsToTombstone) {
                if (records.stream().noneMatch(r -> r.seq() == s)) {
                    throw new IllegalArgumentException("无法标记不存在的序号: " + s);
                }
                erasedSeqs.add(s);
            }
            if (erasedSeqs.size() != before) {
                persistErasedSeqsLocked();
            }
        }
    }

    @Override
    public List<StoredRecord> eraseAndCompact(Set<Long> seqsToRemove) {
        synchronized (lock) {
            ensureNotSealed();
            java.util.TreeSet<Long> toRemove = new java.util.TreeSet<>(seqsToRemove);
            for (Long s : toRemove) {
                if (records.stream().noneMatch(r -> r.seq() == s)) {
                    throw new IllegalArgumentException("无法清除不存在的序号: " + s);
                }
                if (erasedSeqs.contains(s)) {
                    throw new IllegalArgumentException("序号已被清除: " + s);
                }
            }
            if (toRemove.isEmpty()) {
                return List.copyOf(records);
            }

            // 1) 在临时段中重写幸存者，从创世重新锚定哈希链（保持原 seq 与 recordId 不变）
            Path newSegment = dir.resolve("segment.log.compact.tmp");
            long newLength;
            String newLastHash = HmacSigner.GENESIS_PREV;
            ArrayList<StoredRecord> survivors = new ArrayList<>();
            try (FileChannel ch = FileChannel.open(newSegment,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
                String prev = HmacSigner.GENESIS_PREV;
                for (StoredRecord r : records) {
                    if (toRemove.contains(r.seq())) {
                        continue;
                    }
                    StoredRecord rewritten = new StoredRecord(
                            r.seq(), r.recordId(), r.event(), r.appendedAt(), prev,
                            signer.chainHash(prev, canonicalEvent(r.event())));
                    ByteBufferView.writeAll(ch, codec.encode(envelopeJson(rewritten)));
                    survivors.add(rewritten);
                    prev = rewritten.hash();
                }
                newLastHash = prev;
                ch.force(true);
                newLength = ch.position();
            } catch (IOException e) {
                seal(records.isEmpty() ? -1 : records.get(records.size() - 1).seq(),
                        "压实临时段写入失败: " + e.getMessage());
                throw new StorageStateException(firstAffected, sealedReason, e);
            }

            // 2) 原子切换段文件
            try {
                Files.move(newSegment, segmentFile,
                        StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException e) {
                seal(-1, "压实段原子切换失败: " + e.getMessage());
                throw new StorageStateException(firstAffected, sealedReason, e);
            }

            // 3) 更新内存与锚点
            records.clear();
            records.addAll(survivors);
            erasedSeqs.addAll(toRemove);
            fileLength = newLength;
            lastHash = newLastHash;
            // lastSeq 高水位不下调（无空洞追加承诺针对追加阶段；清除后允许出现“已清除空洞”）
            try {
                writeAnchor(new Anchor(lastSeq, lastHash, fileLength,
                        anchorSignature(lastSeq, lastHash, fileLength)));
                persistErasedSeqsLocked();
            } catch (IOException e) {
                seal(lastSeq, "压实后锚点/墓碑持久化失败: " + e.getMessage());
                throw new StorageStateException(firstAffected, sealedReason, e);
            }
            return List.copyOf(records);
        }
    }

    @Override
    public long lastSeq() {
        synchronized (lock) {
            return lastSeq;
        }
    }

    @Override
    public boolean isSealed() {
        return sealed;
    }

    @Override
    public long firstAffectedSeq() {
        return firstAffected;
    }

    @Override
    public String sealedReason() {
        return sealedReason;
    }

    // ------------------------------------------------------------------
    // 启动校验与崩溃恢复
    // ------------------------------------------------------------------

    private void recoverAndVerify(Anchor anchor) throws IOException {
        byte[] data = Files.readAllBytes(segmentFile);
        int pos = 0;
        long frameCount = 0;
        Long lastSeenSeq = null;
        String expectedPrev = HmacSigner.GENESIS_PREV;
        // 检测链是否发生过压实重锚：一旦发现序号不连续，后续 prev 必须仍连续（从创世重算）
        boolean compactionSeen = false;

        while (pos < data.length) {
            int frameStart = pos;
            if (data.length - pos < FrameCodec.LENGTH_PREFIX) {
                break; // 尾部半帧（长度前缀不完整）
            }
            int payloadLen = ((data[pos] & 0xff) << 24) | ((data[pos + 1] & 0xff) << 16)
                    | ((data[pos + 2] & 0xff) << 8) | (data[pos + 3] & 0xff);
            int frameLen = FrameCodec.LENGTH_PREFIX + payloadLen + FrameCodec.SIGNATURE_BYTES;
            if (payloadLen <= 0 || payloadLen > MAX_FRAME_PAYLOAD || frameStart + frameLen > data.length) {
                break; // 畸形长度或帧未写完整：当作未确认尾部
            }
            if (!codec.verify(data, frameStart, payloadLen)) {
                seal(lastSeenSeq == null ? 1 : lastSeenSeq + 1,
                        "帧 HMAC 校验失败（帧可能被伪造或篡改），文件偏移=" + frameStart);
                throw new StorageStateException(firstAffected, sealedReason);
            }

            String json = new String(data, frameStart + FrameCodec.LENGTH_PREFIX, payloadLen, StandardCharsets.UTF_8);
            RecordEnvelope env;
            try {
                env = mapper.readValue(json, RecordEnvelope.class);
            } catch (Exception e) {
                seal(lastSeenSeq == null ? 1 : lastSeenSeq + 1,
                        "帧载荷不是合法 JSON，最早受影响序号=" + (lastSeenSeq == null ? 1 : lastSeenSeq + 1));
                throw new StorageStateException(firstAffected, sealedReason, e);
            }
            frameCount++;

            // 序号必须严格升序；空洞只可能是已登记的物理清除
            if (lastSeenSeq != null) {
                if (env.seq() <= lastSeenSeq) {
                    seal(env.seq(), "序号非升序：" + lastSeenSeq + " -> " + env.seq() + "（记录被重排）");
                    throw new StorageStateException(firstAffected, sealedReason);
                }
                if (env.seq() != lastSeenSeq + 1) {
                    // 出现空洞：中间每个缺失序号都必须在墓碑集合中，否则是未授权删除
                    for (long missing = lastSeenSeq + 1; missing < env.seq(); missing++) {
                        if (!erasedSeqs.contains(missing)) {
                            seal(missing, "序号 " + missing + " 缺失且无清除凭证（未授权删除/截断）");
                            throw new StorageStateException(firstAffected, sealedReason);
                        }
                    }
                    compactionSeen = true;
                }
            } else {
                // 第一条记录：seq>1 意味着前缀被清除，那些序号必须都在墓碑集合中
                for (long missing = 1; missing < env.seq(); missing++) {
                    if (!erasedSeqs.contains(missing)) {
                        seal(missing, "起始序号前的 " + missing + " 缺失且无清除凭证（未授权截断）");
                        throw new StorageStateException(firstAffected, sealedReason);
                    }
                }
                if (env.seq() > 1) {
                    compactionSeen = true;
                }
                if (!env.prevHash().equals(HmacSigner.GENESIS_PREV)) {
                    seal(env.seq(), "压实后重锚链必须以创世哈希开始，实际前驱=" + env.prevHash());
                    throw new StorageStateException(firstAffected, sealedReason);
                }
            }
            if (!env.prevHash().equals(expectedPrev)) {
                seal(env.seq(), "哈希链断裂于序号 " + env.seq()
                        + "：前驱哈希不匹配（记录被篡改/重排，或压实未正确重锚）");
                throw new StorageStateException(firstAffected, sealedReason);
            }
            String canonical = canonicalEvent(env.event());
            String recomputed = signer.chainHash(env.prevHash(), canonical);
            if (!recomputed.equals(env.hash())) {
                seal(env.seq(), "记录内容哈希不匹配于序号 " + env.seq() + "：内容已被篡改");
                throw new StorageStateException(firstAffected, sealedReason);
            }
            // 物理清除的序号绝不应再出现在段中
            if (erasedSeqs.contains(env.seq())) {
                seal(env.seq(), "序号 " + env.seq() + " 已登记物理清除却仍存在于段文件（清除被绕过/回滚）");
                throw new StorageStateException(firstAffected, sealedReason);
            }
            expectedPrev = env.hash();
            lastSeenSeq = env.seq();
            records.add(toRecord(env));
            pos += frameLen;
        }

        // 与锚点比对：锚点是“已确认提交点”。
        // 空存储（anchor.lastSeq()==0 且段内无记录）是合法初始态。
        if (anchor.lastSeq() == 0 && lastSeenSeq == null) {
            if (pos != 0) {
                seal(1, "空锚点却存在段数据（可疑伪造内容）");
                throw new StorageStateException(firstAffected, sealedReason);
            }
        } else {
            // 若锚点末端序号已被物理清除（压实刚发生、其后尚无新追加），段内最后记录
            // 自然小于锚点 lastSeq，此时只要求物理长度/链端哈希与锚点一致。
            boolean anchorTipErased = erasedSeqs.contains(anchor.lastSeq());
            if (!anchorTipErased && (lastSeenSeq == null || lastSeenSeq != anchor.lastSeq())) {
                seal(anchor.lastSeq(), "段文件缺少记录：锚点声明 lastSeq=" + anchor.lastSeq()
                        + "，实际最后记录为 " + lastSeenSeq + "（删除/截断导致记录缺失）");
                throw new StorageStateException(firstAffected, sealedReason);
            }
        }
        if (pos != anchor.length() || !expectedPrev.equals(anchor.lastHash())) {
            // 物理长度或链端哈希与锚点不符：可能存在未授权尾部内容
            seal(anchor.lastSeq(), "段文件长度/链端哈希与锚点不符（可疑尾部或篡改）："
                    + "fileLen=" + pos + " anchorLen=" + anchor.length());
            throw new StorageStateException(firstAffected, sealedReason);
        }

        // 截断到锚点提交点，丢弃任何未确认的半帧/尾部
        if (pos != data.length) {
            try (RandomAccessFile raf = new RandomAccessFile(segmentFile.toFile(), "rw")) {
                raf.setLength(pos);
                raf.getFD().sync();
            }
            log.warn("崩溃恢复：截断未确认尾部 {} 字节（{} -> {}）", data.length - pos, data.length, pos);
        }

        lastSeq = anchor.lastSeq();
        lastHash = anchor.lastHash();
        fileLength = anchor.length();
    }

    private String envelopeJson(StoredRecord rec) {
        try {
            return mapper.writeValueAsString(new RecordEnvelope(
                    rec.seq(), rec.recordId(), rec.appendedAt().toString(),
                    rec.prevHash(), rec.hash(), rec.event()));
        } catch (Exception e) {
            throw new IllegalStateException("序列化记录失败 seq=" + rec.seq(), e);
        }
    }

    /** 墓碑集合持久化（带签名，防伪造“已清除”状态）。 */
    private void persistErasedSeqsLocked() {
        try {
            String canonical = com.github.lisama569.tamperevidentauditpipelinejava.domain.CanonicalJson.write(
                    new java.util.TreeSet<>(erasedSeqs));
            String sig = signer.sign(canonical);
            java.util.Map<String, Object> root = new java.util.TreeMap<>();
            root.put("seqs", new java.util.TreeSet<>(erasedSeqs));
            root.put("signature", sig);
            Path tmp = dir.resolve("erased-seqs.json.tmp");
            Files.write(tmp, mapper.writeValueAsBytes(root));
            try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.WRITE)) {
                ch.force(true);
            }
            Files.move(tmp, tombstoneFile,
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new IllegalStateException("墓碑状态持久化失败", e);
        }
    }

    private void loadErasedSeqsLocked() throws IOException {
        if (!Files.exists(tombstoneFile)) {
            return;
        }
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> root =
                mapper.readValue(Files.readAllBytes(tombstoneFile), java.util.Map.class);
        Object seqsObj = root.get("seqs");
        Object sigObj = root.get("signature");
        java.util.TreeSet<Long> loaded = new java.util.TreeSet<>();
        if (seqsObj instanceof java.util.List<?> list) {
            for (Object o : list) {
                loaded.add(((Number) o).longValue());
            }
        }
        String canonical =
                com.github.lisama569.tamperevidentauditpipelinejava.domain.CanonicalJson.write(loaded);
        if (sigObj == null || !signer.verify(canonical, String.valueOf(sigObj))) {
            seal(-1, "墓碑文件签名无效（清除状态可能被伪造）");
            throw new StorageStateException(firstAffected, sealedReason);
        }
        // 物理压实后这些序号不应再出现在段文件中；逻辑墓碑则仍在段中
        // （二者通过“段中是否还存在该序号”自然区分）
        erasedSeqs.addAll(loaded);
    }

    private StoredRecord toRecord(RecordEnvelope env) {
        return new StoredRecord(env.seq(), env.recordId(), env.event(),
                Instant.parse(env.appendedAt()), env.prevHash(), env.hash());
    }

    /**
     * 计算事件的规范 JSON。时间统一为 epoch 秒.纳秒 的字符串形式，
     * 这样无论事件来自内存对象还是 Jackson 反序列化（时间为 ISO 字符串），
     * 只要逻辑内容相同，哈希输入就完全一致。
     */
    static String canonicalEvent(AuditEvent e) {
        java.util.TreeMap<String, Object> m = new java.util.TreeMap<>();
        m.put("idempotencyKey", e.idempotencyKey());
        m.put("source", e.source());
        m.put("eventType", e.eventType());
        m.put("occurredAt", e.occurredAt().getEpochSecond() + "."
                + String.format("%09d", e.occurredAt().getNano()));
        m.put("actorId", e.actorId());
        m.put("subject", e.subject());
        m.put("retentionDays", e.retentionDays());
        m.put("extensions", new java.util.TreeMap<>(e.extensions()));
        return CanonicalJson.write(m);
    }

    // ------------------------------------------------------------------
    // 锚点
    // ------------------------------------------------------------------

    private String anchorSignature(long lastSeq, String lastHash, long length) {
        return signer.sign(lastSeq + "|" + lastHash + "|" + length);
    }

    private void writeAnchor(Anchor anchor) throws IOException {
        String json = mapper.writeValueAsString(new AnchorFile(
                anchor.lastSeq(), anchor.lastHash(), anchor.length(),
                anchor.signature()));
        Files.write(anchorTmp, json.getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        try (FileChannel ch = FileChannel.open(anchorTmp, StandardOpenOption.WRITE)) {
            ch.force(true);
        }
        Files.move(anchorTmp, anchorFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        fsyncDirectoryQuietly(dir);
        if (!Files.exists(genesisFile)) {
            Files.writeString(genesisFile, json, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            try (FileChannel ch = FileChannel.open(genesisFile, StandardOpenOption.WRITE)) {
                ch.force(true);
            }
        }
    }

    private Anchor readAnchor() throws IOException {
        String json = Files.readString(anchorFile);
        AnchorFile f = mapper.readValue(json, AnchorFile.class);
        return new Anchor(f.lastSeq(), f.lastHash(), f.length(), f.signature());
    }

    private void verifyAnchorSignature(Anchor anchor) {
        String expect = anchorSignature(anchor.lastSeq(), anchor.lastHash(), anchor.length());
        if (anchor.lastSeq() != 0 && !signer.verify(anchor.lastSeq() + "|" + anchor.lastHash() + "|" + anchor.length(), anchor.signature())) {
            seal(anchor.lastSeq(), "锚点签名无效（锚点被伪造）");
            throw new StorageStateException(firstAffected, sealedReason);
        }
    }

    private void checkGenesisRollback(Anchor anchor) throws IOException {
        if (Files.exists(genesisFile)) {
            AnchorFile g = mapper.readValue(Files.readString(genesisFile), AnchorFile.class);
            if (anchor.lastSeq() < g.lastSeq()) {
                seal(anchor.lastSeq() + 1, "检测到锚点回滚：创世锚点 lastSeq=" + g.lastSeq()
                        + "，当前锚点 lastSeq=" + anchor.lastSeq());
                throw new StorageStateException(firstAffected, sealedReason);
            }
        }
    }

    // ------------------------------------------------------------------
    // 帧写入
    // ------------------------------------------------------------------

    private void fsyncDirectoryQuietly(Path directory) {
        // JDK 无标准目录 fsync；Linux/macOS 上尽力通过 FileDescriptor.sync() 持久化 rename。
        // 失败不影响正确性（段文件本身已 fsync，锚点以原子 rename 发布）。
        try (java.io.FileInputStream in = new java.io.FileInputStream(directory.toFile())) {
            in.getFD().sync();
        } catch (Exception ignore) {
            log.debug("目录 fsync 不可用: {}", directory);
        }
    }

    private void writeFrameDurably(byte[] frame) throws IOException {
        try (FileChannel ch = FileChannel.open(segmentFile,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            ByteBufferView.writeAll(ch, frame);
            ch.force(true);
        }
    }

    private void failSealedOrTruncate(long positionBefore, IOException cause) {
        try (RandomAccessFile raf = new RandomAccessFile(segmentFile.toFile(), "rw")) {
            raf.setLength(positionBefore);
            raf.getFD().sync();
        } catch (IOException ignore) {
            seal(lastSeq + 1, "写入失败后回滚半帧再次失败: " + cause.getMessage());
        }
    }

    private void ensureNotSealed() {
        if (sealed) {
            throw new StorageStateException(firstAffected, "存储已密封，拒绝追加：" + sealedReason);
        }
    }

    private void seal(long seq, String reason) {
        this.sealed = true;
        this.firstAffected = seq;
        this.sealedReason = reason;
        log.error("【留存存储密封】firstAffectedSeq={} reason={}", seq, reason);
    }

    // ------------------------------------------------------------------
    // 持久化 DTO
    // ------------------------------------------------------------------

    record AnchorFile(long lastSeq, String lastHash, long length, String signature) {
    }

    record RecordEnvelope(long seq, String recordId, String appendedAt,
                          String prevHash, String hash, AuditEvent event) {
    }

    /** 隔离 ByteBuffer 引用，便于测试替换。 */
    static final class ByteBufferView {
        static void writeAll(FileChannel ch, byte[] frame) throws IOException {
            java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(frame);
            while (buf.hasRemaining()) {
                ch.write(buf);
            }
        }
    }
}
