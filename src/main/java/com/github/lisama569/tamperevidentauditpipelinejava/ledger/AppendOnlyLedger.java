package com.github.lisama569.tamperevidentauditpipelinejava.ledger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.zip.CRC32;

/**
 * 防篡改只追加账本（v2：外部锚点 + 分段锚 + 懒解密 + 可解释清除）。
 *
 * <p>磁盘形态（ledger.log，逐行一个 JSON 帧）：
 * <ul>
 *   <li>DATA 帧：{pos, seq(数据序号), kind=DATA, key(幂等键), stored, eventTime, prev, hash,
 *       body(base64(iv||AES-GCM(payload))), crc(body-b64 CRC32)}；每条记录独立随机 DEK，存于 keys/{seq}.key。</li>
 *   <li>PURGE 帧（v2）：{pos, kind=PURGE, dataSeq, source(RETENTION/COMPLIANCE), requestId, reason,
 *       stored, prev, hash}；旧版本 PURGE 帧无 source/requestId，按旧公式兼容校验。</li>
 *   <li>CHECKPOINT 帧（v2）：{pos, kind=CHECKPOINT, afterDataSeq, prev, hash}，
 *       每 N 条 DATA 出现一次，作为分段核验锚点（帧位占 pos，不占数据序号）。</li>
 *   <li>UPGRADE 帧（v2）：老目录首次以新版本打开时追加的升级边界标记。</li>
 * </ul>
 *
 * <p>外部锚点文件 ledger.log.anchor（与 ledger.log 同目录，原子替换写盘）：
 * {pos(最后帧位), dataSeq(最后数据序号), tailHash(最后一帧 hash), legacy, boundaryDataSeq,
 * checkpoints:[{after,pos,offset,hash}], updatedAt, hmac}。
 *
 * <p>保证：
 * <ul>
 *   <li>并发追加串行化；数据序号唯一无空洞；写完 force 落盘。崩溃留下的物理不完整尾部在打开时截断。</li>
 *   <li>HMAC 哈希链（密钥在账本外 keys/hmac.key）：篡改内容/删除任意一条/删除末尾一条或多条/相邻互换
 *       都会在校验时暴露，firstTamperedSequence 为最早受影响的数据序号；
 *       锚点保证“删除末尾完整记录”与“半行截断”在重启后依然可判定，不依赖运行期内存。</li>
 *   <li>一旦破坏：账本进入 closed，拒绝一切追加与清除；重开结论一致。</li>
 *   <li>恢复只做线性哈希校验，不解密（懒加载），几万条记录的重启耗时可控；
 *       CHECKPOINT 支持只核验一段，分段拼接结论与全量一致。</li>
 *   <li>清除 = 追加 PURGE 帧后删除 DEK（加密擦除）：链与 envelope 可验证，明文不可恢复，
 *       来源（到期/合规）、请求标识与原因随链留存可审计。</li>
 *   <li>老目录（无锚点）首次打开走兼容升级：追加 UPGRADE 帧、写入锚点，
 *       并明确报告兼容边界（升级前的尾部删除不在新核验能力覆盖范围内）。</li>
 * </ul>
 */
public class AppendOnlyLedger {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int GCM_TAG_BITS = 128;

    static final String KIND_DATA = "DATA";
    static final String KIND_PURGE = "PURGE";
    static final String KIND_CHECKPOINT = "CHECKPOINT";
    static final String KIND_UPGRADE = "UPGRADE";

    private final Path ledgerFile;
    private final Path anchorFile;
    private final Path anchorTmpFile;
    private final Path keyDir;
    private final byte[] hmacKey;
    private final int checkpointInterval;

    private final List<Frame> frames = new ArrayList<>();
    private final TreeMap<Long, StoredEvent> bySeq = new TreeMap<>();
    private final Map<String, StoredEvent> byIdemKey = new java.util.HashMap<>();
    private final TreeMap<Long, PurgeMark> purgeMarks = new TreeMap<>();
    /** 持久化于锚点的 CHECKPOINT 索引：key=afterDataSeq，value=描述。 */
    private final TreeMap<Long, CheckpointAnchor> checkpoints = new TreeMap<>();

    private String lastHash = "";
    private long lastPos;
    private long lastDataSeq;
    private boolean closed;
    private long firstTampered = -1L;
    private boolean legacyMode;
    private long legacyBoundaryDataSeq;

    public AppendOnlyLedger(Path ledgerFile) {
        try {
            this.ledgerFile = ledgerFile;
            Files.createDirectories(ledgerFile.toAbsolutePath().getParent());
            this.keyDir = ledgerFile.toAbsolutePath().getParent().resolve("keys");
            Files.createDirectories(keyDir);
            this.anchorFile = ledgerFile.toAbsolutePath().getParent()
                    .resolve(ledgerFile.getFileName() + ".anchor");
            this.anchorTmpFile = ledgerFile.toAbsolutePath().getParent()
                    .resolve(ledgerFile.getFileName() + ".anchor.tmp");
            this.hmacKey = loadOrCreateHmacKey();
            int interval = Integer.getInteger("audit.ledger.checkpointInterval", 1000);
            this.checkpointInterval = Math.max(1, interval);
            recover();
        } catch (IOException e) {
            throw new IllegalStateException("无法初始化账本: " + ledgerFile, e);
        }
    }

    /**
     * 降级打开：检测到篡改时不抛出，返回一个已 closed 的实例（已解析记录只读可查，追加/清除一律拒绝）。
     */
    public static AppendOnlyLedger openDegraded(Path ledgerFile) {
        try {
            return new AppendOnlyLedger(ledgerFile);
        } catch (TamperException t) {
            return t.ledger();
        }
    }

    // ---------------------------------------------------------------- append

    public synchronized StoredEvent append(String idempotencyKey, String payloadJson, long eventTimeMs) {
        ensureOpen("追加");
        long now = System.currentTimeMillis();
        long dataSeq = lastDataSeq + 1L;
        long pos = lastPos + 1L;
        try {
            byte[] dek = newDek();
            String body = encrypt(dek, payloadJson.getBytes(StandardCharsets.UTF_8));
            long crc = crc32(body.getBytes(StandardCharsets.UTF_8));
            String hash = hmac(frameDataString(dataSeq, idempotencyKey, now, eventTimeMs, body, crc, pos, lastHash));

            // 先写 DEK 再落帧：保证“帧可见 ⇒ DEK 已存在”，崩溃不会把未完成的写入误判成私删
            Path keyFilePath = keyFile(dataSeq);
            Files.write(keyFilePath, dek);
            trySetOwnerOnly(keyFilePath);

            long frameOffset = Files.exists(ledgerFile) ? Files.size(ledgerFile) : 0L;
            ObjectNode frame = MAPPER.createObjectNode();
            frame.put("pos", pos);
            frame.put("seq", dataSeq);
            frame.put("kind", KIND_DATA);
            frame.put("key", idempotencyKey);
            frame.put("stored", now);
            frame.put("eventTime", eventTimeMs);
            frame.put("prev", nullToEmpty(lastHash));
            frame.put("hash", hash);
            frame.put("body", body);
            frame.put("crc", crc);
            writeFrame(frame);

            StoredEvent event = new StoredEvent(dataSeq, idempotencyKey, payloadJson,
                    hash, nullToEmpty(lastHash), now, false);
            frames.add(new Frame(frame, event, frameOffset));
            bySeq.put(dataSeq, event);
            byIdemKey.put(idempotencyKey, event);
            lastHash = hash;
            lastPos = pos;
            lastDataSeq = dataSeq;

            maybeWriteCheckpoint();
            writeAnchor();
            return event;
        } catch (IOException e) {
            throw new IllegalStateException("账本写入失败: " + e.getMessage(), e);
        }
    }

    // ---------------------------------------------------------------- reads

    public synchronized Optional<StoredEvent> findByIdempotencyKey(String key) {
        return Optional.ofNullable(byIdemKey.get(key));
    }

    /** 全部 DATA 记录（含 envelope）；正常账本调用会触发明文懒解密，清除记录载荷为 null。
     *  账本已 closed（破坏降级）时只返回内存 envelope，不再触碰可能缺失/损坏的 DEK。 */
    public synchronized List<StoredEvent> all() {
        List<StoredEvent> out = new ArrayList<>(bySeq.size());
        for (Long seq : new ArrayList<>(bySeq.keySet())) {
            StoredEvent e = bySeq.get(seq);
            if (!closed && !e.purged() && e.payloadJson() == null) {
                e = materialize(seq);
            }
            out.add(e);
        }
        return out;
    }

    public synchronized Optional<StoredEvent> at(long sequence) {
        StoredEvent e = bySeq.get(sequence);
        if (e == null) {
            return Optional.empty();
        }
        if (!closed && !e.purged() && e.payloadJson() == null) {
            e = materialize(sequence);
        }
        return Optional.of(e);
    }

    /** 取明文（不清密的记录懒解密）；已清除返回 null；closed 降级时不再解密，直接返回 null；
     *  正常账本上 DEK 缺失/解密失败按破坏处理。 */
    public synchronized String payloadAt(long sequence) {
        StoredEvent e = bySeq.get(sequence);
        if (e == null || e.purged() || closed) {
            return null;
        }
        if (e.payloadJson() == null) {
            e = materialize(sequence);
        }
        return e.payloadJson();
    }

    public synchronized int count() {
        return bySeq.size();
    }

    public synchronized long nextSequence() {
        return lastDataSeq + 1L;
    }

    public synchronized boolean isClosed() {
        return closed;
    }

    public synchronized long firstTamperedSequence() {
        return firstTampered;
    }

    /** 是否为老数据目录升级而来（兼容模式）。 */
    public synchronized boolean legacyMode() {
        return legacyMode;
    }

    /** 升级边界：升级时已存在的数据序号；该边界之前的历史不具备新核验能力（尾部删除检测）。 */
    public synchronized long legacyBoundaryDataSeq() {
        return legacyBoundaryDataSeq;
    }

    public synchronized int checkpointInterval() {
        return checkpointInterval;
    }

    public synchronized Optional<PurgeMark> purgeMark(long dataSeq) {
        return Optional.ofNullable(purgeMarks.get(dataSeq));
    }

    public synchronized List<PurgeMark> purgeMarks() {
        return new ArrayList<>(purgeMarks.values());
    }

    // ---------------------------------------------------------------- purge

    /** 到期清除（旧入口，等价于 RETENTION 来源）。 */
    public synchronized void markPurged(long sequence) {
        markPurged(sequence, PurgeMark.SOURCE_RETENTION, null, "保留到期清除");
    }

    /**
     * 追加 PURGE 标记帧（链内可审计），随后删除 DEK 完成加密擦除。
     * DEK 已删除（重启重放）时保持幂等；已清除记录直接返回，不重复处理。
     */
    public synchronized void markPurged(long sequence, String source, String requestId, String reason) {
        ensureOpen("标记清除");
        StoredEvent event = bySeq.get(sequence);
        if (event == null) {
            throw new IllegalArgumentException("记录不存在: " + sequence);
        }
        if (event.purged()) {
            return;
        }
        long now = System.currentTimeMillis();
        long pos = lastPos + 1L;
        String src = source == null ? PurgeMark.SOURCE_RETENTION : source;
        String req = requestId == null ? "" : requestId;
        String why = reason == null ? "" : reason;
        String hash = hmac(pos + "|PURGE|" + sequence + "|" + src + "|" + req + "|" + why
                + "|" + now + "|" + nullToEmpty(lastHash));
        ObjectNode frame = MAPPER.createObjectNode();
        frame.put("pos", pos);
        frame.put("kind", KIND_PURGE);
        frame.put("dataSeq", sequence);
        frame.put("source", src);
        frame.put("requestId", req);
        frame.put("reason", why);
        frame.put("stored", now);
        frame.put("prev", nullToEmpty(lastHash));
        frame.put("hash", hash);
        try {
            writeFrame(frame);
            Files.deleteIfExists(keyFile(sequence));
        } catch (IOException e) {
            throw new IllegalStateException("写入清除标记失败: " + e.getMessage(), e);
        }
        applyPurgeState(sequence, new PurgeMark(sequence, src, req, why, now));
        frames.add(new Frame(frame, bySeq.get(sequence), -1L));
        lastHash = hash;
        lastPos = pos;
        writeAnchor();
    }

    // ---------------------------------------------------------------- verify

    /**
     * 全量核验（内存视图）：帧链 HMAC/CRC/序号 + DEK 在位兜底；最早受影响数据序号；正常返回 -1。
     * 结论与打开时一致：若打开时已判破坏（closed），直接返回已定位的序号，不重新洗白。
     */
    public synchronized long verify() {
        if (closed) {
            return firstTampered;
        }
        ScanAccumulator acc = scanFrames(frames, 1L, lastDataSeq);
        // 未授权私删 DEK 兜底：已清除记录除外（其密钥缺失是预期）
        for (StoredEvent e : bySeq.values()) {
            if (e.purged()) {
                continue;
            }
            if (!Files.exists(keyFile(e.sequence()))) {
                if (acc.earliest < 0L || e.sequence() < acc.earliest) {
                    acc.earliest = e.sequence();
                    acc.basis = "序号" + e.sequence() + "无清除标记但DEK缺失（未授权删除）";
                }
            }
        }
        return acc.earliest;
    }

    /**
     * 分段核验 DATA 序号区间（闭区间）。物理上从 {@code fromSeqInclusive} 之前最近的 CHECKPOINT
     * 锚点开始扫描，因此多段拼接的结论与一次性全量核验一致；核验期间并发追加只影响锁时点的快照，
     * 不会误报已稳定的历史，也不会漏掉范围内真破坏。
     */
    public synchronized VerifyResult verifyRangeData(long fromSeqInclusive, long toSeqInclusive) {
        long from = Math.max(1L, fromSeqInclusive);
        long to = Math.min(lastDataSeq, toSeqInclusive);
        // 1) 找起点：afterDataSeq < from 的最近 CHECKPOINT；没有则从创世开始
        Map.Entry<Long, CheckpointAnchor> anchorEntry = checkpoints.lowerEntry(from);
        int startIndex = 0;
        long contextData = 0L;
        String startPrev = "";
        if (anchorEntry != null) {
            CheckpointAnchor cp = anchorEntry.getValue();
            startIndex = frameIndexOfPos(cp.pos()) + 1;
            contextData = cp.afterDataSeq();
            startPrev = cp.hash();
        }
        // 2) 收集范围内帧：DATA 帧到上下文序号越过 to 为止；PURGE/CHECKPOINT 等非DATA帧随其后包含
        List<Frame> slice = new ArrayList<>();
        long dataCount = contextData;
        for (int i = startIndex; i < frames.size(); i++) {
            Frame fr = frames.get(i);
            JsonNode n = fr.node;
            String kind = n.path("kind").asText();
            long ctxBefore = dataCount;
            if (KIND_DATA.equals(kind)) {
                dataCount++;
                if (ctxBefore >= to) {
                    break;
                }
            } else if (KIND_CHECKPOINT.equals(kind)) {
                dataCount = Math.max(dataCount, n.path("afterDataSeq").asLong());
                if (ctxBefore > to) {
                    break;
                }
            } else if (ctxBefore > to) {
                break;
            }
            slice.add(fr);
        }
        ScanAccumulator acc = scanFrames(slice, from, to, startPrev, contextData);
        long anchoredAfter = anchorEntry == null ? 0L : anchorEntry.getKey();
        if (acc.earliest < 0L) {
            return VerifyResult.healthy(from, to, slice.size(), anchoredAfter,
                    "从 afterDataSeq=" + anchoredAfter + " 的CHECKPOINT锚点起逐帧HMAC+CRC+序号校验");
        }
        long reported = acc.earliest < from ? from : acc.earliest;
        return VerifyResult.tampered(from, to, reported, slice.size(), anchoredAfter,
                "范围内最早破坏帧 reportedSeq=" + acc.earliest + "，映射到区间起点=" + reported);
    }

    /**
     * 分段核验（直接读盘，不依赖本次进程内存中的帧列表）：使用锚点中持久化的 CHECKPOINT 偏移定位，
     * 有界扫描 [from,to]。停服、改文件、换进程后结论一致。
     */
    public synchronized VerifyResult verifyRangeDataFromDisk(long fromSeqInclusive, long toSeqInclusive) throws IOException {
        long from = Math.max(1L, fromSeqInclusive);
        long to = Math.min(lastDataSeq, toSeqInclusive);
        Map.Entry<Long, CheckpointAnchor> anchorEntry = checkpoints.lowerEntry(from);
        long startOffset = 0L;
        long contextData = 0L;
        String startPrev = "";
        if (anchorEntry != null) {
            CheckpointAnchor cp = anchorEntry.getValue();
            startOffset = cp.offset() + lineLengthAt(cp.offset());
            contextData = cp.afterDataSeq();
            startPrev = cp.hash();
            // 锚点与实际文件交叉校验：该偏移处必须真的是对应 CHECKPOINT 帧
            JsonNode cpNode = readFirstLineFrom(startOffset == 0 ? 0L : cp.offset());
            if (cpNode == null || !KIND_CHECKPOINT.equals(cpNode.path("kind").asText())
                    || cpNode.path("afterDataSeq").asLong() != cp.afterDataSeq()
                    || !cpNode.path("hash").asText().equals(cp.hash())) {
                return VerifyResult.tampered(from, to, from, 0, contextData,
                        "锚点CHECKPOINT与磁盘内容不一致，afterDataSeq=" + contextData);
            }
        }
        List<JsonNode> slice = new ArrayList<>();
        long dataCount = contextData;
        long fileLen = Files.size(ledgerFile);
        try (RandomAccessFile raf = new RandomAccessFile(ledgerFile.toFile(), "r")) {
            raf.seek(startOffset);
            String raw;
            while ((raw = raf.readLine()) != null) {
                long ctxBefore = dataCount;
                // readLine 按 ISO-8859-1 逐字节读取，这里还原为 UTF-8，避免中文 reason 等多字节内容解析/HMAC 错误
                String line = new String(raw.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
                JsonNode n = parseFrameLine(line);
                if (n == null) {
                    // 锚点之后不应再有物理不完整帧（打开时已截断）；出现即破坏
                    return VerifyResult.tampered(from, to,
                            ctxBefore >= from ? ctxBefore + 1 : from, slice.size(), contextData,
                            "锚点之后存在无法解析的帧");
                }
                String kind = n.path("kind").asText();
                if (KIND_DATA.equals(kind)) {
                    dataCount++;
                } else if (KIND_CHECKPOINT.equals(kind)) {
                    dataCount = Math.max(dataCount, n.path("afterDataSeq").asLong());
                }
                // 收集覆盖 [from,to] 所需的物理帧：起点锚点之后的所有非DATA帧都要，
                // DATA 帧则到其上下文序号超过 to 为止
                if (KIND_DATA.equals(kind) && ctxBefore >= to) {
                    break;
                }
                if (!KIND_DATA.equals(kind) && ctxBefore > to) {
                    break;
                }
                slice.add(n);
                if (raf.getFilePointer() >= fileLen) {
                    break;
                }
            }
        }
        ScanAccumulator acc = scanNodes(slice, from, to, startPrev, contextData);
        long anchoredAfter = anchorEntry == null ? 0L : anchorEntry.getKey();
        if (acc.earliest < 0L) {
            return VerifyResult.healthy(from, to, slice.size(), anchoredAfter,
                    "直接读盘：从afterDataSeq=" + anchoredAfter+"锚点起HMAC+CRC+序号校验");
        }
        long reported = acc.earliest < from ? from : acc.earliest;
        return VerifyResult.tampered(from, to, reported, slice.size(), anchoredAfter,
                "读盘核验最早破坏reportedSeq=" + acc.earliest);
    }

    // ------------------------------------------------------------ recovery

    private void recover() throws IOException {
        boolean anchorPresent = Files.exists(anchorFile);
        long fileSize = Files.exists(ledgerFile) ? Files.size(ledgerFile) : 0L;
        if ((fileSize == 0L) && !anchorPresent) {
            Files.createDirectories(ledgerFile.getParent());
            if (!Files.exists(ledgerFile)) {
                Files.createFile(ledgerFile);
            }
            lastHash = "";
            writeAnchor(); // 空账本即具备 v2 能力
            return;
        }

        byte[] rawBytes = fileSize == 0L ? new byte[0] : Files.readAllBytes(ledgerFile);
        AnchorState anchor = anchorPresent ? readAnchor() : null;
        boolean validAnchor = anchor != null;
        boolean containsUpgrade = containsKind(rawBytes, KIND_UPGRADE);

        // 1) 物理不完整尾部处理
        long cutLen = completePrefixLength(rawBytes);
        boolean hasTornTail = cutLen < rawBytes.length;
        if (hasTornTail) {
            if (validAnchor) {
                // v2 账本：撕裂内容保留待锚点比对（末尾删/半行截断要判破坏），文件先截断
                truncateTo(cutLen);
            } else if (containsUpgrade) {
                // 升级过但锚点丢失 → 破坏
                closeAsTampered(1L, "升级标记存在但锚点文件缺失");
                throw tamperException();
            } else {
                // 老目录：崩溃撕裂沿用旧行为，静默截断
                truncateTo(cutLen);
            }
            rawBytes = Files.readAllBytes(ledgerFile);
        }

        if (!validAnchor) {
            if (containsUpgrade) {
                closeAsTampered(1L, "检测到UPGRADE升级帧但锚点文件缺失（疑似删除锚点回退）");
                replayFrames(rawBytes);
                throw tamperException();
            }
            // 老目录兼容升级：重放校验通过后追加 UPGRADE 帧并写锚点
            ScanAccumulator acc = replayFrames(rawBytes);
            if (acc.earliest >= 0L) {
                closeAsTampered(acc.earliest, "老目录升级重放即发现破坏");
                throw tamperException();
            }
            this.legacyMode = true;
            this.legacyBoundaryDataSeq = lastDataSeq;
            if (lastDataSeq > 0L) {
                appendUpgradeFrame();
            }
            rebuildCheckpointsFromFrames();
            writeAnchor();
            return;
        }

        // 2) v2 正常打开：重放完整帧
        ScanAccumulator acc = replayFrames(rawBytes);

        // 3) 锚点对账：末尾整帧缺失（删除末尾一条或多条 / 半行截断）
        if (anchor.pos > lastPos) {
            long gapSeq = lastDataSeq + 1L;
            if (gapSeq < acc.earliest || acc.earliest < 0L) {
                acc.earliest = gapSeq;
                acc.basis = "锚点声明最后帧位=" + anchor.pos + "，实际完整帧位=" + lastPos
                        + "，末尾删除的第一个空缺数据序号=" + gapSeq;
            }
        }
        if (acc.earliest >= 0L) {
            closeAsTampered(acc.earliest,
                    "打开账本时检测到破坏，最早受影响数据序号=" + acc.earliest + "，依据：" + acc.basis);
            throw tamperException();
        }

        // 4) 锚点滞后（帧已落盘、锚点未及更新即崩溃）：信任已校验的链，补齐锚点
        this.legacyMode = anchor.legacy;
        this.legacyBoundaryDataSeq = anchor.boundaryDataSeq;
        rebuildCheckpointsFromFrames();
        if (anchor.pos != lastPos || !anchor.tailHash.equals(lastHash)) {
            writeAnchor();
        }
    }

    /** 顺序重放，构建内存索引；返回最早破坏序号（同时完成 PURGE 收齐与 DEK 缺失判定）。 */
    private ScanAccumulator replayFrames(byte[] rawBytes) throws IOException {
        List<JsonNode> nodes = new ArrayList<>();
        List<Long> offsets = new ArrayList<>();
        int p = 0;
        while (p < rawBytes.length) {
            int nl = indexOfByte(rawBytes, (byte) '\n', p);
            int end = nl < 0 ? rawBytes.length : nl;
            String line = new String(rawBytes, p, end - p, StandardCharsets.UTF_8);
            if (!line.isBlank()) {
                JsonNode n = parseFrameLine(line);
                if (n != null) {
                    nodes.add(n);
                    offsets.add((long) p);
                }
            }
            if (nl < 0) {
                break;
            }
            p = nl + 1;
        }
        frames.clear();
        for (int i = 0; i < nodes.size(); i++) {
            frames.add(new Frame(nodes.get(i), null, offsets.get(i)));
        }

        ScanAccumulator acc = scanNodes(nodes, 1L, Long.MAX_VALUE, "", 0L);

        // 构建 DATA 索引（懒解密，不在恢复路径读 DEK）
        String prev = "";
        long dataSeqSeen = 0L;
        java.util.Set<Long> purgeSet = new java.util.HashSet<>();
        for (Frame f : frames) {
            JsonNode n = f.node;
            String kind = n.path("kind").asText();
            if (KIND_DATA.equals(kind)) {
                long seq = n.path("seq").asLong();
                dataSeqSeen = seq;
                StoredEvent event = new StoredEvent(seq, n.path("key").asText(), null,
                        n.path("hash").asText(), n.path("prev").asText(),
                        n.path("stored").asLong(), false, n.path("body").asText());
                bySeq.put(seq, event);
                byIdemKey.put(event.idempotencyKey(), event);
                f.event = event;
                lastDataSeq = Math.max(lastDataSeq, seq);
            } else if (KIND_PURGE.equals(kind)) {
                purgeSet.add(n.path("dataSeq").asLong());
            } else if (KIND_CHECKPOINT.equals(kind)) {
                long after = n.path("afterDataSeq").asLong();
                checkpoints.put(after, new CheckpointAnchor(after, n.path("pos").asLong(),
                        f.offset, n.path("hash").asText()));
            }
            lastPos = Math.max(lastPos, n.path("pos").asLong());
            prev = n.path("hash").asText();
        }
        lastHash = prev;

        // 收齐 PURGE：补删 DEK（崩溃在“标记落盘、密钥未删”之间）并装载清除状态
        for (Frame f : frames) {
            JsonNode n = f.node;
            if (KIND_PURGE.equals(n.path("kind").asText())) {
                long seq = n.path("dataSeq").asLong();
                purgeSet.add(seq);
                Files.deleteIfExists(keyFile(seq));
                String src = n.hasNonNull("source") ? n.path("source").asText()
                        : PurgeMark.SOURCE_RETENTION;
                String req = n.hasNonNull("requestId") ? n.path("requestId").asText() : "";
                String why = n.hasNonNull("reason") ? n.path("reason").asText()
                        : (PurgeMark.SOURCE_RETENTION.equals(src) ? "保留到期清除" : "");
                applyPurgeState(seq, new PurgeMark(seq, src, req, why, n.path("stored").asLong()));
            }
        }
        // 无 PURGE 标记却 DEK 缺失：未授权私删 → 破坏（懒解密时还会再兜底一次）
        for (long seq = 1L; seq <= dataSeqSeen; seq++) {
            StoredEvent e = bySeq.get(seq);
            if (e == null || e.purged()) {
                continue;
            }
            if (!Files.exists(keyFile(seq))) {
                if (acc.earliest < 0L || seq < acc.earliest) {
                    acc.earliest = seq;
                    acc.basis = "序号" + seq + "无PURGE标记但DEK缺失（未授权删除）";
                }
            }
        }
        return acc;
    }

    // ------------------------------------------------------------ scanning

    /** 帧级通用扫描：HMAC + CRC + pos/seq/prev 连续性，返回最早受影响 DATA 序号。 */
    private ScanAccumulator scanFrames(List<Frame> slice, long rangeFrom, long rangeTo) {
        List<JsonNode> nodes = new ArrayList<>(slice.size());
        for (Frame f : slice) {
            nodes.add(f.node);
        }
        // 内存全量/无锚起点：从头开始
        return scanNodes(nodes, rangeFrom, rangeTo, "", 0L);
    }

    private ScanAccumulator scanFrames(List<Frame> slice, long rangeFrom, long rangeTo,
                                       String startPrev, long startDataCount) {
        List<JsonNode> nodes = new ArrayList<>(slice.size());
        for (Frame f : slice) {
            nodes.add(f.node);
        }
        return scanNodes(nodes, rangeFrom, rangeTo, startPrev, startDataCount);
    }

    private ScanAccumulator scanNodes(List<JsonNode> nodes, long rangeFrom, long rangeTo,
                                      String startPrev, long startDataCount) {
        ScanAccumulator acc = new ScanAccumulator();
        String prev = nullToEmpty(startPrev);
        long dataCount = startDataCount;
        boolean fromGenesis = startDataCount == 0L && prev.isEmpty();
        long expectedFramePos = fromGenesis ? 0L : -1L;
        for (JsonNode n : nodes) {
            long pos = n.path("pos").asLong();
            String kind = n.path("kind").asText();
            long relIndex = -1L;
            if (expectedFramePos >= 0L) {
                expectedFramePos++;
                relIndex = expectedFramePos;
            }
            boolean broken = false;
            long reported;
            String recomputed;
            if (KIND_DATA.equals(kind)) {
                long seq = n.path("seq").asLong();
                reported = seq;
                String body = n.path("body").asText();
                recomputed = hmac(frameDataString(seq, n.path("key").asText(),
                        n.path("stored").asLong(), n.path("eventTime").asLong(),
                        body, n.path("crc").asLong(), pos, prev));
                if (crc32(body.getBytes(StandardCharsets.UTF_8)) != n.path("crc").asLong()) {
                    broken = true;
                }
                long expectedSeq = dataCount + 1L;
                if (seq != expectedSeq) {
                    broken = true;
                    // 数据序号空洞（删除中间记录）：空缺的第一个序号比当前帧更早
                    if (rangeContains(rangeFrom, rangeTo, expectedSeq)
                            && (acc.earliest < 0L || expectedSeq < acc.earliest)) {
                        acc.earliest = expectedSeq;
                        acc.basis = "DATA序号空洞：期望" + expectedSeq + "实际" + seq;
                    }
                }
                dataCount = seq;
            } else if (KIND_PURGE.equals(kind)) {
                long seq = n.path("dataSeq").asLong();
                reported = seq;
                recomputed = recomputePurgeHmac(n, pos, prev);
            } else if (KIND_CHECKPOINT.equals(kind)) {
                long after = n.path("afterDataSeq").asLong();
                reported = after + 1L;
                recomputed = hmac(pos + "|CHECKPOINT|" + after + "|" + prev);
                if (after != dataCount) {
                    broken = true;
                }
            } else if (KIND_UPGRADE.equals(kind)) {
                reported = dataCount + 1L;
                recomputed = hmac(pos + "|UPGRADE|" + n.path("stored").asLong() + "|" + prev);
            } else {
                reported = dataCount + 1L;
                recomputed = "__unknown_kind__";
                broken = true;
            }
            if (relIndex >= 0L && pos != relIndex) {
                broken = true; // 帧位错乱：删帧/重排
            }
            if (!prev.equals(n.path("prev").asText())) {
                broken = true;
            }
            if (!recomputed.equals(n.path("hash").asText())) {
                broken = true;
            }
            if (broken && rangeContains(rangeFrom, rangeTo, reported)
                    && (acc.earliest < 0L || reported < acc.earliest)) {
                acc.earliest = reported;
                if (acc.basis == null) {
                    acc.basis = "帧pos=" + pos + " kind=" + kind + " HMAC/prev/pos/seq校验失败";
                }
            }
            prev = n.path("hash").asText();
        }
        return acc;
    }

    private static boolean rangeContains(long from, long to, long seq) {
        return seq >= from && seq <= to;
    }

    private String recomputePurgeHmac(JsonNode n, long pos, String prev) {
        if (n.hasNonNull("source")) {
            return hmac(pos + "|PURGE|" + n.path("dataSeq").asLong() + "|"
                    + n.path("source").asText() + "|" + n.path("requestId").asText("") + "|"
                    + n.path("reason").asText("") + "|" + n.path("stored").asLong() + "|" + prev);
        }
        // 老版本 PURGE 帧兼容公式
        return hmac(pos + "|PURGE|" + n.path("dataSeq").asLong() + "|"
                + PurgeMark.SOURCE_RETENTION + "|" + n.path("stored").asLong() + "|" + prev);
    }

    // ------------------------------------------------------------ anchor

    private record AnchorState(long pos, long dataSeq, String tailHash, boolean legacy,
                               long boundaryDataSeq, List<CheckpointAnchor> checkpoints) {
    }

    private record CheckpointAnchor(long afterDataSeq, long pos, long offset, String hash) {
    }

    private static final class ScanAccumulator {
        long earliest = -1L;
        String basis;
    }

    private AnchorState readAnchor() throws IOException {
        try {
            JsonNode n = MAPPER.readTree(anchorFile.toFile());
            long pos = n.path("pos").asLong(-1L);
            long dataSeq = n.path("dataSeq").asLong(-1L);
            String tailHash = n.path("tailHash").asText("");
            boolean legacy = n.path("legacy").asBoolean(false);
            long boundary = n.path("boundaryDataSeq").asLong(0L);
            String expectHmac = n.path("hmac").asText();
            List<CheckpointAnchor> cps = new ArrayList<>();
            StringBuilder cpCanonical = new StringBuilder();
            if (n.has("checkpoints") && n.path("checkpoints").isArray()) {
                for (JsonNode cp : n.path("checkpoints")) {
                    long after = cp.path("after").asLong();
                    long cpPos = cp.path("pos").asLong();
                    long cpOffset = cp.path("offset").asLong();
                    String cpHash = cp.path("hash").asText();
                    cps.add(new CheckpointAnchor(after, cpPos, cpOffset, cpHash));
                    cpCanonical.append(after).append(':').append(cpPos).append(':')
                            .append(cpOffset).append(':').append(cpHash).append(';');
                }
            }
            String canonical = "ANCHOR|" + pos + "|" + dataSeq + "|" + tailHash + "|"
                    + legacy + "|" + boundary + "|" + cpCanonical;
            if (!hmac(canonical).equals(expectHmac)) {
                return null; // 锚点本身被伪造/破坏
            }
            return new AnchorState(pos, dataSeq, tailHash, legacy, boundary, cps);
        } catch (Exception e) {
            return null;
        }
    }

    private synchronized void writeAnchor() {
        try {
            ObjectNode n = MAPPER.createObjectNode();
            n.put("pos", lastPos);
            n.put("dataSeq", lastDataSeq);
            n.put("tailHash", nullToEmpty(lastHash));
            n.put("legacy", legacyMode);
            n.put("boundaryDataSeq", legacyBoundaryDataSeq);
            ArrayNode arr = n.putArray("checkpoints");
            StringBuilder cpCanonical = new StringBuilder();
            for (CheckpointAnchor cp : checkpoints.values()) {
                ObjectNode c = arr.addObject();
                c.put("after", cp.afterDataSeq());
                c.put("pos", cp.pos());
                c.put("offset", cp.offset());
                c.put("hash", cp.hash());
                cpCanonical.append(cp.afterDataSeq()).append(':').append(cp.pos()).append(':')
                        .append(cp.offset()).append(':').append(cp.hash()).append(';');
            }
            n.put("updatedAt", System.currentTimeMillis());
            String canonical = "ANCHOR|" + lastPos + "|" + lastDataSeq + "|" + nullToEmpty(lastHash)
                    + "|" + legacyMode + "|" + legacyBoundaryDataSeq + "|" + cpCanonical;
            n.put("hmac", hmac(canonical));
            byte[] bytes = (n.toString() + "\n").getBytes(StandardCharsets.UTF_8);
            try (FileChannel ch = FileChannel.open(anchorTmpFile, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                ch.write(ByteBuffer.wrap(bytes));
                ch.force(true);
            }
            try {
                Files.move(anchorTmpFile, anchorFile, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicUnsupported) {
                Files.move(anchorTmpFile, anchorFile, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new IllegalStateException("锚点写入失败: " + e.getMessage(), e);
        }
    }

    private void maybeWriteCheckpoint() throws IOException {
        if (lastDataSeq % checkpointInterval != 0L) {
            return;
        }
        long pos = lastPos + 1L;
        long after = lastDataSeq;
        String hash = hmac(pos + "|CHECKPOINT|" + after + "|" + nullToEmpty(lastHash));
        long offset = Files.size(ledgerFile);
        ObjectNode frame = MAPPER.createObjectNode();
        frame.put("pos", pos);
        frame.put("kind", KIND_CHECKPOINT);
        frame.put("afterDataSeq", after);
        frame.put("prev", nullToEmpty(lastHash));
        frame.put("hash", hash);
        writeFrame(frame);
        frames.add(new Frame(frame, null, offset));
        checkpoints.put(after, new CheckpointAnchor(after, pos, offset, hash));
        lastHash = hash;
        lastPos = pos;
    }

    private void appendUpgradeFrame() throws IOException {
        long pos = lastPos + 1L;
        long now = System.currentTimeMillis();
        String hash = hmac(pos + "|UPGRADE|" + now + "|" + nullToEmpty(lastHash));
        long offset = Files.size(ledgerFile);
        ObjectNode frame = MAPPER.createObjectNode();
        frame.put("pos", pos);
        frame.put("kind", KIND_UPGRADE);
        frame.put("stored", now);
        frame.put("prev", nullToEmpty(lastHash));
        frame.put("hash", hash);
        writeFrame(frame);
        frames.add(new Frame(frame, null, offset));
        lastHash = hash;
        lastPos = pos;
    }

    private void rebuildCheckpointsFromFrames() {
        checkpoints.clear();
        for (Frame f : frames) {
            JsonNode n = f.node;
            if (KIND_CHECKPOINT.equals(n.path("kind").asText())) {
                long after = n.path("afterDataSeq").asLong();
                checkpoints.put(after, new CheckpointAnchor(after, n.path("pos").asLong(),
                        f.offset, n.path("hash").asText()));
            }
        }
    }

    private int frameIndexOfPos(long pos) {
        for (int i = 0; i < frames.size(); i++) {
            if (frames.get(i).node.path("pos").asLong() == pos) {
                return i;
            }
        }
        return -1;
    }

    private long lineLengthAt(long offset) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(ledgerFile.toFile(), "r")) {
            raf.seek(offset);
            String line = raf.readLine();
            return line == null ? 0L : line.getBytes(StandardCharsets.ISO_8859_1).length + 1L;
        }
    }

    private JsonNode readFirstLineFrom(long offset) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(ledgerFile.toFile(), "r")) {
            raf.seek(offset);
            String line = raf.readLine();
            return line == null ? null : parseFrameLine(new String(line.getBytes(StandardCharsets.ISO_8859_1),
                    StandardCharsets.UTF_8));
        }
    }

    // ------------------------------------------------------------ internals

    private void ensureOpen(String action) {
        if (closed) {
            throw new TamperException(firstTampered,
                    "账本已因检测到破坏而关闭(最早受影响序号=" + firstTampered + ")，拒绝" + action)
                    .withLedger(this);
        }
    }

    private void closeAsTampered(long seq, String why) {
        closed = true;
        firstTampered = seq;
    }

    private TamperException tamperException() {
        return new TamperException(firstTampered,
                "账本破坏：最早受影响数据序号=" + firstTampered).withLedger(this);
    }

    private void applyPurgeState(long sequence, PurgeMark mark) {
        purgeMarks.put(sequence, mark);
        StoredEvent ev = bySeq.get(sequence);
        if (ev != null && !ev.purged()) {
            StoredEvent purged = ev.asPurged();
            bySeq.put(sequence, purged);
            byIdemKey.put(ev.idempotencyKey(), purged);
            for (Frame fr : frames) {
                if (fr.event != null && fr.event.sequence() == sequence) {
                    fr.event = purged;
                }
            }
        }
    }

    private StoredEvent materialize(long seq) {
        StoredEvent e = bySeq.get(seq);
        if (e == null || e.purged()) {
            return e;
        }
        Path kf = keyFile(seq);
        if (!Files.exists(kf)) {
            closeAsTampered(seq, "序号" + seq + "的DEK缺失且无清除标记（未授权删除）");
            throw new TamperException(seq, "序号" + seq + "的DEK缺失，判定为未授权删除").withLedger(this);
        }
        try {
            String plain = new String(decrypt(Files.readAllBytes(kf), e.bodyB64()), StandardCharsets.UTF_8);
            StoredEvent loaded = e.withPayload(plain);
            bySeq.put(seq, loaded);
            byIdemKey.put(loaded.idempotencyKey(), loaded);
            for (Frame fr : frames) {
                if (fr.event != null && fr.event.sequence() == seq) {
                    fr.event = loaded;
                }
            }
            return loaded;
        } catch (TamperException t) {
            throw t;
        } catch (Exception ex) {
            closeAsTampered(seq, "序号" + seq + "解密失败（密文或DEK被破坏）");
            throw new TamperException(seq, "序号" + seq + "解密失败").withLedger(this);
        }
    }

    private static int indexOfByte(byte[] bytes, byte target, int from) {
        for (int i = from; i < bytes.length; i++) {
            if (bytes[i] == target) {
                return i;
            }
        }
        return -1;
    }

    /** 完整前缀字节长度：若文件以换行结束则全完整，否则最后一个换行之后视为不完整。 */
    private static long completePrefixLength(byte[] bytes) {        if (bytes.length == 0 || bytes[bytes.length - 1] == (byte) '\n') {
            return bytes.length;
        }
        int cut = bytes.length - 1;
        while (cut > 0 && bytes[cut] != (byte) '\n') {
            cut--;
        }
        return bytes[cut] == (byte) '\n' ? cut + 1L : 0L;
    }

    private void truncateTo(long length) throws IOException {
        try (FileChannel ch = FileChannel.open(ledgerFile, StandardOpenOption.WRITE)) {
            ch.truncate(length);
            ch.force(true);
        }
    }

    private boolean containsKind(byte[] rawBytes, String kind) {
        String text = new String(rawBytes, StandardCharsets.UTF_8);
        return text.contains("\"kind\":\"" + kind + "\"");
    }

    private void writeFrame(ObjectNode frame) throws IOException {
        byte[] bytes = (MAPPER.writeValueAsString(frame) + "\n").getBytes(StandardCharsets.UTF_8);
        try (FileChannel ch = FileChannel.open(ledgerFile,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            ch.write(ByteBuffer.wrap(bytes));
            ch.force(true);
        }
    }

    private JsonNode parseFrameLine(String line) {
        try {
            JsonNode n = MAPPER.readTree(line);
            if (n == null || !n.hasNonNull("pos") || !n.hasNonNull("kind") || !n.hasNonNull("hash")) {
                return null;
            }
            return n;
        } catch (Exception e) {
            return null;
        }
    }

    private Path keyFile(long dataSeq) {
        return keyDir.resolve(dataSeq + ".key");
    }

    private byte[] loadOrCreateHmacKey() throws IOException {
        Path f = keyDir.resolve("hmac.key");
        if (Files.exists(f)) {
            return Files.readAllBytes(f);
        }
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        Files.write(f, key);
        trySetOwnerOnly(f);
        return key;
    }

    private static void trySetOwnerOnly(Path p) {
        try {
            p.toFile().setReadable(false, false);
            p.toFile().setWritable(false, false);
            p.toFile().setReadable(true, true);
            p.toFile().setWritable(true, true);
        } catch (Exception ignore) {
            // 某些平台不支持 POSIX 权限时忽略
        }
    }

    private static byte[] newDek() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            return kg.generateKey().getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("无法生成 DEK", e);
        }
    }

    private static String encrypt(byte[] dek, byte[] plain) {
        try {
            byte[] iv = new byte[12];
            RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ct = cipher.doFinal(plain);
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            return Base64.getEncoder().encodeToString(out);
        } catch (Exception e) {
            throw new IllegalStateException("加密失败", e);
        }
    }

    private static byte[] decrypt(byte[] dek, String bodyB64) {
        try {
            byte[] all = Base64.getDecoder().decode(bodyB64);
            byte[] iv = new byte[12];
            System.arraycopy(all, 0, iv, 0, 12);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            return cipher.doFinal(all, 12, all.length - 12);
        } catch (Exception e) {
            throw new IllegalStateException("解密失败（数据可能被篡改）", e);
        }
    }

    private String hmac(String input) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            byte[] d = mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("HMAC 计算失败", e);
        }
    }

    private static String frameDataString(long seq, String idemKey, long stored, long eventTime,
                                          String bodyB64, long crc, long pos, String prevHash) {
        return pos + "|DATA|" + seq + "|" + idemKey + "|" + stored + "|" + eventTime + "|"
                + bodyB64 + "|" + crc + "|" + nullToEmpty(prevHash);
    }

    private static long crc32(byte[] bytes) {
        CRC32 crc = new CRC32();
        crc.update(bytes);
        return crc.getValue();
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static final class Frame {
        final JsonNode node;
        volatile StoredEvent event;
        final long offset;

        Frame(JsonNode node, StoredEvent event, long offset) {
            this.node = node;
            this.event = event;
            this.offset = offset;
        }
    }
}
