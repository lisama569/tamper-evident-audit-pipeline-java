package com.github.lisama569.tamperevidentauditpipelinejava.ledger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.PurgeSource;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.security.SecureRandom;
import java.util.zip.CRC32;

/**
 * 防篡改只追加账本（v2：写入意图 + 已提交锚点 + 分段核验 + 老目录升级）。
 *
 * <p>磁盘形态（ledger.log，逐行一个 JSON 帧）：
 * <ul>
 *   <li>DATA 帧：{pos, seq, kind=DATA, key(幂等键), stored(写入时间ms), eventTime(事件时间ms),
 *       prev(前一帧 hash), hash(本帧 HMAC), body(base64(iv||AES-GCM(canonicalPayload))), crc(body-b64 CRC32)}；
 *       每条记录独立随机 DEK，存于 keys/{seq}.key。</li>
 *   <li>PURGE 帧（v2）：{pos, kind=PURGE, dataSeq, source(EXPIRY/COMPLIANCE), requestId, reason,
 *       stored, prev, hash}；老版本 PURGE 帧没有 source/requestId，按 EXPIRY 兼容重算。</li>
 * </ul>
 *
 * <p>崩溃原子性（keys/ 位于攻击者触达不到的位置）：
 * <ol>
 *   <li>写帧前先原子落盘 HMAC 签名的“写入意图” keys/intent.json，APPEND 还先写好 DEK；</li>
 *   <li>帧 + 换行 force 落盘后，原子更新“已提交锚点” keys/anchor.json，再删意图。</li>
 * </ol>
 * 重启时：有合法意图但帧没写完 → 判定为自身崩溃，回滚半帧（无半条可见）；
 * <b>没有合法意图却出现半帧/来源不明完整帧 → 判定为破坏</b>。
 *
 * <p>破坏检测覆盖：内容篡改、中间删帧、末尾整删（相对已提交锚点）、相邻互换、半条收尾、
 * 私删 DEK；结论给出最早受影响数据序号与 {@link TamperEvidence} 证据类型。
 * 结论完全由磁盘内容 + HMAC 锚点重算，重启后一致，不依赖运行期内存。
 * 一旦破坏：账本 closed，拒绝一切追加与清除标记。
 *
 * <p>清除 = 追加 PURGE 帧（链内可审计：谁、因何、何时、来源）后删除独立 DEK（加密擦除）。
 *
 * <p>老目录（无 keys/format.json）按 v1 打开：全链重放通过后原地升级到 v2 并给出
 * {@link CompatibilityReport}，明确说明新增能力的生效范围（锚点保护从升级提交点开始）。
 */
public class AppendOnlyLedger {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int GCM_TAG_BITS = 128;
    static final int FORMAT_VERSION = 2;

    private final Path ledgerFile;
    private final Path keyDir;
    private final Path metaDir;          // keys/
    private final Path checkpointDir;   // keys/checkpoints/
    private final Path anchorFile;
    private final Path formatFile;
    private final Path intentFile;
    private final byte[] hmacKey;
    private final int checkpointInterval;

    private final List<Frame> frames = new ArrayList<>();
    private final Map<Long, StoredEvent> bySeq = new HashMap<>();
    private final Map<String, StoredEvent> byIdemKey = new HashMap<>();

    private String lastHash = "";
    private long lastPos;
    private long lastDataSeq;
    private boolean closed;
    private long firstTampered = -1L;
    private TamperEvidence evidence = TamperEvidence.OK;
    private String tamperDetail = "OK";
    private CompatibilityReport compatibilityReport;

    public AppendOnlyLedger(Path ledgerFile) {
        this(ledgerFile, 1000);
    }

    public AppendOnlyLedger(Path ledgerFile, int checkpointInterval) {
        try {
            this.ledgerFile = ledgerFile;
            this.checkpointInterval = Math.max(1, checkpointInterval);
            Files.createDirectories(ledgerFile.toAbsolutePath().getParent());
            this.keyDir = ledgerFile.toAbsolutePath().getParent().resolve("keys");
            this.metaDir = keyDir;
            this.checkpointDir = keyDir.resolve("checkpoints");
            this.anchorFile = keyDir.resolve("anchor.json");
            this.formatFile = keyDir.resolve("format.json");
            this.intentFile = keyDir.resolve("intent.json");
            Files.createDirectories(keyDir);
            this.hmacKey = loadOrCreateHmacKey();
            recover();
        } catch (IOException e) {
            throw new IllegalStateException("无法初始化账本: " + ledgerFile, e);
        }
    }

    /**
     * 降级打开：检测到篡改时不抛出，返回已 closed 的实例（只读查询可用，追加/清除一律拒绝）。
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
        ensureOpen("拒绝追加");
        long now = System.currentTimeMillis();
        long dataSeq = lastDataSeq + 1L;
        long pos = lastPos + 1L;
        try {
            byte[] dek = newDek();
            String body = encrypt(dek, payloadJson.getBytes(StandardCharsets.UTF_8));
            long crc = crc32(body.getBytes(StandardCharsets.UTF_8));
            String hash = hmac(frameDataString(dataSeq, idempotencyKey, now, eventTimeMs, body, crc, pos, lastHash));

            ObjectNode frame = MAPPER.createObjectNode();
            frame.put("pos", pos);
            frame.put("seq", dataSeq);
            frame.put("kind", "DATA");
            frame.put("key", idempotencyKey);
            frame.put("stored", now);
            frame.put("eventTime", eventTimeMs);
            frame.put("prev", nullToEmpty(lastHash));
            frame.put("hash", hash);
            frame.put("body", body);
            frame.put("crc", crc);

            // 崩溃原子协议：意图 -> DEK -> 帧 -> 锚点。任一中间环节崩溃，重启都能得出确定结论。
            writeIntent("APPEND", dataSeq, pos, "", null, "");
            Path keyFile = keyFile(dataSeq);
            Files.write(keyFile, dek);
            trySetOwnerOnly(keyFile);
            writeFrame(frame);
            commitAnchor(pos, dataSeq, hash);
            deleteIntent();

            StoredEvent event = StoredEvent.fresh(dataSeq, idempotencyKey, payloadJson,
                    hash, nullToEmpty(lastHash), now, eventTimeMs);
            frames.add(new Frame(frame, event));
            bySeq.put(dataSeq, event);
            byIdemKey.put(idempotencyKey, event);
            lastHash = hash;
            lastPos = pos;
            lastDataSeq = dataSeq;
            maybeWriteCheckpoint(dataSeq, pos, hash);
            return event;
        } catch (IOException e) {
            throw new IllegalStateException("账本写入失败: " + e.getMessage(), e);
        }
    }

    // ---------------------------------------------------------------- reads

    public synchronized Optional<StoredEvent> findByIdempotencyKey(String key) {
        return Optional.ofNullable(byIdemKey.get(key));
    }

    public synchronized List<StoredEvent> all() {
        return new ArrayList<>(bySeq.values());
    }

    public synchronized Optional<StoredEvent> at(long sequence) {
        return Optional.ofNullable(bySeq.get(sequence));
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

    public synchronized TamperEvidence evidence() {
        return evidence;
    }

    public synchronized String tamperDetail() {
        return tamperDetail;
    }

    public synchronized int frameCount() {
        return frames.size();
    }

    public synchronized CompatibilityReport compatibilityReport() {
        return compatibilityReport;
    }

    // ---------------------------------------------------------------- purge

    /** 到期清除（兼容旧入口）。 */
    public synchronized void markPurged(long sequence) {
        markPurged(sequence, PurgeSource.EXPIRY, null, "RETENTION");
    }

    /**
     * 追加 PURGE 标记帧（链内可审计：source/requestId/reason），随后删除 DEK 完成加密擦除。
     * 已清除记录幂等无操作；账本 closed 时明确拒绝。
     */
    public synchronized void markPurged(long sequence, PurgeSource source, String requestId, String reason) {
        ensureOpen("拒绝标记清除");
        StoredEvent event = bySeq.get(sequence);
        if (event == null) {
            throw new IllegalArgumentException("记录不存在: " + sequence);
        }
        if (event.purged()) {
            return; // 已清过的记录不再重复处理
        }
        PurgeSource src = source == null ? PurgeSource.EXPIRY : source;
        String why = reason == null ? "" : reason;
        long now = System.currentTimeMillis();
        long pos = lastPos + 1L;
        String hash = hmac(purgeFrameString(pos, sequence, src.name(), requestId, why, now, lastHash, true));

        ObjectNode frame = MAPPER.createObjectNode();
        frame.put("pos", pos);
        frame.put("kind", "PURGE");
        frame.put("dataSeq", sequence);
        frame.put("source", src.name());
        if (requestId != null) {
            frame.put("requestId", requestId);
        }
        frame.put("reason", why);
        frame.put("stored", now);
        frame.put("prev", nullToEmpty(lastHash));
        frame.put("hash", hash);
        try {
            writeIntent("PURGE", sequence, pos, src.name(), requestId, why);
            writeFrame(frame);
            Files.deleteIfExists(keyFile(sequence));
            commitAnchor(pos, lastDataSeq, hash);
            deleteIntent();
        } catch (IOException e) {
            throw new IllegalStateException("写入清除标记失败: " + e.getMessage(), e);
        }
        StoredEvent purged = event.asPurged(src, requestId, why, now);
        bySeq.put(sequence, purged);
        byIdemKey.put(event.idempotencyKey(), purged);
        for (int i = 0; i < frames.size(); i++) {
            StoredEvent ev = frames.get(i).event;
            if (ev != null && ev.sequence() == sequence) {
                frames.set(i, new Frame(frames.get(i).node, purged));
            }
        }
        frames.add(new Frame(frame, purged));
        lastHash = hash;
        lastPos = pos;
    }

    // ---------------------------------------------------------------- verify

    /** 全量核验：返回最早受影响数据序号；健康返回 -1。 */
    public long verify() {
        return verifyFull().firstTamperedSequence();
    }

    /**
     * 全量核验当前磁盘上的账本：重新读盘重算（不依赖内存态），并比对已提交锚点检测末尾整删。
     * 并发追加期间调用：以进入时刻的已提交前缀为范围，追加到一半的新帧不纳入本次结论。
     */
    public VerifyResult verifyFull() {
        Snapshot snap;
        synchronized (this) {
            // 帧快照与锚点必须在同一把锁内取：保证核验范围恰好是某个已提交前缀，
            // 并发追加推进锚点时不会把“还没进快照的新帧”误报成末尾缺失。
            snap = new Snapshot(new ArrayList<>(frames), lastDataSeq, lastPos, closed, readAnchorOrNull());
        }
        return verifyFrames(snap.frames, 0L, "", snap.lastDataSeq, snap.frames.size(), false, true,
                snap.anchor);
    }

    /**
     * 分段核验数据序号闭区间 [fromSequence, toSequence] 内的帧：
     * 起点使用 keys/checkpoints 中的签名检查点（from=1 用创世空 hash），
     * 只重算该段帧，不必从头全量；多段拼起来的结论与 {@link #verifyFull()} 一致。
     * 返回结论明确带 fromSequence/toSequence。
     */
    public synchronized VerifyResult verifyRange(long fromSequence, long toSequence) {
        if (fromSequence < 1L || toSequence < fromSequence) {
            throw new IllegalArgumentException("非法核验区间: [" + fromSequence + "," + toSequence + "]");
        }
        long seedSeq = fromSequence - 1L;
        long seedPos;
        String seedHash;
        boolean fromCheckpoint;
        if (seedSeq == 0L) {
            seedPos = 0L;
            seedHash = "";
            fromCheckpoint = false;
        } else {
            ObjectNode cp = readCheckpoint(seedSeq);
            if (cp == null) {
                throw new IllegalStateException("序号 " + seedSeq + " 处没有签名检查点，无法从该边界分段核验；"
                        + "请从 1 全量核验或选择已有检查点边界");
            }
            seedPos = cp.path("pos").asLong();
            seedHash = cp.path("hash").asText("");
            fromCheckpoint = true;
        }
        // 段尾：toSequence 的 DATA 帧位置（优先检查点），否则取内存中该 DATA 帧位置
        long endPos;
        ObjectNode endCp = readCheckpoint(toSequence);
        List<Frame> snapshot = new ArrayList<>(frames);
        if (endCp != null) {
            endPos = endCp.path("pos").asLong();
        } else {
            Long p = locateDataFramePos(snapshot, toSequence);
            if (p == null) {
                return new VerifyResult(false, fromSequence, TamperEvidence.MIDDLE_FRAME_MISSING,
                        "核验区间尾部序号 " + toSequence + " 在账本中不存在（可能已被删除）",
                        fromSequence, toSequence, 0, fromCheckpoint);
            }
            endPos = p;
        }
        List<Frame> segment = new ArrayList<>();
        for (Frame f : snapshot) {
            long p = f.node.path("pos").asLong();
            if (p > seedPos && p <= endPos) {
                segment.add(f);
            }
        }
        return verifyFrames(segment, seedPos, seedHash, toSequence, snapshot.size(),
                fromCheckpoint, false, null);
    }

    /** 在当前已提交位置强制写一个签名检查点（测试与运维可用）。 */
    public synchronized void writeCheckpointNow() {
        try {
            writeCheckpoint(lastDataSeq, lastPos, lastHash);
        } catch (IOException e) {
            throw new IllegalStateException("检查点写入失败", e);
        }
    }

    /** 检查点间隔（每追加多少条 DATA 落一个签名检查点）。 */
    public int checkpointInterval() {
        return checkpointInterval;
    }

    // ------------------------------------------------------------ recovery

    private void recover() throws IOException {
        boolean legacy = !Files.exists(formatFile);
        if (!Files.exists(ledgerFile)) {
            Files.createDirectories(ledgerFile.getParent());
            Files.createFile(ledgerFile);
        }
        byte[] rawBytes = Files.readAllBytes(ledgerFile);

        // 1) 拆出完整帧行与可能的尾部半帧
        List<String> completeLines = new ArrayList<>();
        int lastNl = -1;
        for (int i = 0; i < rawBytes.length; i++) {
            if (rawBytes[i] == (byte) '\n') {
                completeLines.add(new String(rawBytes, lastNl + 1, i - lastNl - 1, StandardCharsets.UTF_8));
                lastNl = i;
            }
        }
        String partial = lastNl + 1 < rawBytes.length
                ? new String(rawBytes, lastNl + 1, rawBytes.length - lastNl - 1, StandardCharsets.UTF_8)
                : null;

        Anchor anchor = legacy ? null : readAnchorOrNull();

        // 2) 顺序重放所有完整帧，收集最早破坏候选（结构 + HMAC + CRC + DEK）
        List<TamperCandidate> candidates = new ArrayList<>();
        Map<Long, PurgeMark> purgeMarks = new LinkedHashMap<>();
        List<Long> keyProblems = new ArrayList<>();
        List<Long> dataSeqInFileOrder = new ArrayList<>();
        String prev = "";
        long expectedPos = 0L;
        long dataCount = 0L;
        for (String line : completeLines) {
            if (line.isBlank()) {
                continue;
            }
            JsonNode n = parseFrameLine(line);
            expectedPos++;
            long pos = n == null ? expectedPos : n.path("pos").asLong(expectedPos);
            String kind = n == null ? "" : n.path("kind").asText();
            if (n == null) {
                candidates.add(new TamperCandidate(dataCount + 1L, TamperEvidence.CHAIN_TAMPERED,
                        "存在无法解析的完整帧行 pos<=" + pos));
                prev = "UNPARSEABLE:" + pos;
                continue;
            }
            boolean posBad = pos != expectedPos;
            boolean prevBad = !prev.equals(n.path("prev").asText());
            long reported;
            String recomputed;
            boolean crcBad = false;
            if ("DATA".equals(kind)) {
                long seq = n.path("seq").asLong();
                reported = seq;
                String body = n.path("body").asText();
                boolean dataV1 = !n.has("eventTime");
                recomputed = dataV1
                        ? hmac(frameDataStringV1(seq, n.path("key").asText(),
                                n.path("stored").asLong(), body, n.path("crc").asLong(), pos, prev))
                        : hmac(frameDataString(seq, n.path("key").asText(),
                                n.path("stored").asLong(), n.path("eventTime").asLong(0L),
                                body, n.path("crc").asLong(), pos, prev));
                crcBad = crc32(body.getBytes(StandardCharsets.UTF_8)) != n.path("crc").asLong();
                dataCount++;
                dataSeqInFileOrder.add(seq);
            } else if ("PURGE".equals(kind)) {
                long seq = n.path("dataSeq").asLong();
                reported = seq;
                boolean v2 = n.has("source");
                PurgeSource src = v2 ? parseSource(n.path("source").asText()) : PurgeSource.EXPIRY;
                purgeMarks.put(seq, new PurgeMark(src, n.path("requestId").asText(null),
                        n.path("reason").asText(""), n.path("stored").asLong(), v2));
                recomputed = hmac(purgeFrameString(pos, seq, src.name(),
                        n.path("requestId").asText(null), n.path("reason").asText(""),
                        n.path("stored").asLong(), prev, v2));
            } else {
                reported = dataCount + 1L;
                recomputed = "__UNKNOWN_KIND__";
            }
            boolean hmacBad = !recomputed.equals(n.path("hash").asText());
            classifyFrame(candidates, reported, posBad, prevBad, crcBad, hmacBad, n, kind);
            prev = n.path("hash").asText();

            Frame frame = new Frame(n, null);
            frames.add(frame);
            lastPos = Math.max(lastPos, pos);
            if ("DATA".equals(kind)) {
                long seq = n.path("seq").asLong();
                String payload = null;
                boolean keyProblem = false;
                if (Files.exists(keyFile(seq))) {
                    try {
                        payload = new String(decrypt(Files.readAllBytes(keyFile(seq)),
                                n.path("body").asText()), StandardCharsets.UTF_8);
                    } catch (Exception e) {
                        keyProblem = true;
                    }
                } else {
                    keyProblem = true;
                }
                if (keyProblem) {
                    keyProblems.add(seq);
                }
                StoredEvent event = StoredEvent.replayed(seq, n.path("key").asText(), payload,
                        n.path("hash").asText(), n.path("prev").asText(),
                        n.path("stored").asLong(),
                        n.has("eventTime") ? n.path("eventTime").asLong() : n.path("stored").asLong());
                bySeq.put(seq, event);
                byIdemKey.put(event.idempotencyKey(), event);
                frame.event = event;
                lastDataSeq = Math.max(lastDataSeq, seq);
            }
        }
        lastHash = prev;

        // DATA 序号流整体分析：相邻互换 → REORDERED（钉较小序号）；序号向前跳变 → MIDDLE_FRAME_MISSING
        analyzeDataSequenceFlow(dataSeqInFileOrder, candidates);

        // 3) 尾部半帧 / 越界完整帧 / 末尾整删
        ObjectNode intent = readIntentOrNull();
        boolean crashRecovered = false;
        if (partial != null && !partial.isBlank()) {
            if (legacy) {
                // v1 目录：沿用旧规则（崩溃撕裂截断），并在兼容报告里留痕
                truncateAfterCompleteFrames(rawBytes, completeLines);
                compatibilityNote("v1 目录尾部无换行的不完整帧按旧版本语义截断（崩溃撕裂）");
            } else {
                boolean intentMatchesPending = intent != null
                        && (frameForPos(frames, intent.path("pos").asLong()) == null);
                if (intentMatchesPending) {
                    // 自身崩溃在写帧途中（有签名写入意图、帧未完成）：回滚半帧与孤立 DEK/意图，账本保持健康
                    truncateAfterCompleteFrames(rawBytes, completeLines);
                    rollbackIntent(intent);
                    crashRecovered = true;
                    partial = null;
                } else if (looksLikeFrameFragment(partial)) {
                    // 能解析成帧形态、却没有任何合法写入意图：不是正常崩溃撕裂，判为破坏
                    long partialSeq = guessPartialDataSeq(partial, lastDataSeq + 1L);
                    candidates.add(new TamperCandidate(partialSeq, TamperEvidence.HALF_FRAME_TAIL,
                            "账本末尾出现没有合法写入意图的半条帧（已能识别为帧片段，疑似被中断的伪造/真帧截断），"
                                    + "起始数据序号=" + partialSeq));
                } else {
                    // 无法解析成帧的杂散字节：按崩溃撕裂处理（与 v1 语义一致，避免把磁盘脏字节误报为攻击）
                    truncateAfterCompleteFrames(rawBytes, completeLines);
                    compatibilityNote("v2 目录尾部存在无法识别为帧的不完整字节，按崩溃撕裂截断");
                    partial = null;
                }
            }
        }

        // 已提交锚点之后的完整帧：合法崩溃补提交，否则判来源不明
        if (anchor != null) {
            List<Frame> beyond = new ArrayList<>();
            for (Frame f : frames) {
                if (f.node.path("pos").asLong() > anchor.pos) {
                    beyond.add(f);
                }
            }
            if (!beyond.isEmpty()) {
                boolean committable = false;
                if (beyond.size() == 1 && intent != null
                        && intent.path("pos").asLong() == beyond.get(0).node.path("pos").asLong()) {
                    Frame f = beyond.get(0);
                    String kind = f.node.path("kind").asText();
                    String recompute = "DATA".equals(kind)
                            ? (f.node.has("eventTime")
                                ? hmac(frameDataString(f.node.path("seq").asLong(), f.node.path("key").asText(),
                                    f.node.path("stored").asLong(), f.node.path("eventTime").asLong(0L),
                                    f.node.path("body").asText(), f.node.path("crc").asLong(),
                                    f.node.path("pos").asLong(), anchor.hash))
                                : hmac(frameDataStringV1(f.node.path("seq").asLong(), f.node.path("key").asText(),
                                    f.node.path("stored").asLong(), f.node.path("body").asText(),
                                    f.node.path("crc").asLong(), f.node.path("pos").asLong(), anchor.hash)))
                            : hmac(purgeFrameString(f.node.path("pos").asLong(), f.node.path("dataSeq").asLong(),
                            f.node.path("source").asText(PurgeSource.EXPIRY.name()),
                            f.node.path("requestId").asText(null), f.node.path("reason").asText(""),
                            f.node.path("stored").asLong(), anchor.hash, f.node.has("source")));
                    committable = recompute.equals(f.node.path("hash").asText());
                }
                if (committable) {
                    Frame f = beyond.get(0);
                    if ("PURGE".equals(f.node.path("kind").asText())) {
                        try {
                            Files.deleteIfExists(keyFile(f.node.path("dataSeq").asLong()));
                        } catch (IOException ignore) {
                            // 下轮重试
                        }
                    }
                    commitAnchor(f.node.path("pos").asLong(), lastDataSeq, f.node.path("hash").asText());
                    rollbackIntent(intent);
                    crashRecovered = true;
                } else {
                    long seq = beyond.get(0).node.path("seq").asLong(anchor.dataSeq + 1L);
                    if (!"DATA".equals(beyond.get(0).node.path("kind").asText())) {
                        seq = anchor.dataSeq + 1L;
                    }
                    candidates.add(new TamperCandidate(seq, TamperEvidence.UNEXPECTED_TAIL_FRAME,
                            "已提交锚点(pos=" + anchor.pos + ")之后出现 " + beyond.size()
                                    + " 个来源不明或无法验签的完整帧，首个数据序号=" + seq));
                }
            }
            if (lastPos < anchor.pos || lastDataSeq < anchor.dataSeq) {
                long missingFrom = lastDataSeq + 1L;
                // 若链自身/半帧已发现破坏，优先报告更早更具体的证据；
                // 锚点比对的职责是“链看起来完好但整条尾部记录缺失”这一它种删法。
                if (!candidates.isEmpty()) {
                    candidates.add(new TamperCandidate(missingFrom, TamperEvidence.TAIL_RECORDS_MISSING,
                            "另：账本比已提交锚点短(锚点 seq=" + anchor.dataSeq + " 实际 seq=" + lastDataSeq
                                    + ")；因已有更早破坏证据，以前者为准"));
                } else {
                    candidates.add(new TamperCandidate(missingFrom, TamperEvidence.TAIL_RECORDS_MISSING,
                            "账本链内帧均验签通过，但比已提交锚点短：锚点到 pos=" + anchor.pos + "/seq="
                                    + anchor.dataSeq + "，实际到 pos=" + lastPos + "/seq=" + lastDataSeq
                                    + "——末尾整条记录被完整删除，第一个空缺数据序号=" + missingFrom));
                }
            }
        }

        // 4) 重放 PURGE 标记：补删 DEK（崩溃在标记落盘与删 DEK 之间，幂等完成）
        for (Map.Entry<Long, PurgeMark> e : purgeMarks.entrySet()) {
            long seq = e.getKey();
            try {
                Files.deleteIfExists(keyFile(seq));
            } catch (IOException ignore) {
                // 下轮重试
            }
            keyProblems.remove(seq);
            StoredEvent ev = bySeq.get(seq);
            PurgeMark mark = e.getValue();
            if (ev != null && !ev.purged()) {
                StoredEvent purged = ev.asPurged(mark.source, mark.requestId, mark.reason, mark.storedAt);
                bySeq.put(seq, purged);
                byIdemKey.put(ev.idempotencyKey(), purged);
                for (int i = 0; i < frames.size(); i++) {
                    StoredEvent sev = frames.get(i).event;
                    if (sev != null && sev.sequence() == seq) {
                        frames.set(i, new Frame(frames.get(i).node, purged));
                    }
                }
            }
        }
        // 5) 无 PURGE 标记却 DEK 缺失/无法解密：未授权删除或密文被破坏
        for (long seq : keyProblems) {
            candidates.add(new TamperCandidate(seq, TamperEvidence.CONTENT_ALTERED,
                    "序号 " + seq + " 的 DEK 缺失或无法解密，且链内没有合法 PURGE 标记（未授权删除）"));
        }

        // 6) 选最早受影响候选（同序号证据优先级：REORDERED > MIDDLE > CHAIN > CONTENT）
        TamperCandidate winner = null;
        for (TamperCandidate c : candidates) {
            if (winner == null || c.seq < winner.seq
                    || (c.seq == winner.seq && evidenceRank(c.evidence) < evidenceRank(winner.evidence))) {
                winner = c;
            }
        }
        if (winner != null) {
            closed = true;
            firstTampered = winner.seq;
            evidence = winner.evidence;
            tamperDetail = winner.detail;
            throw new TamperException(winner.seq,
                    "检测到账本破坏：证据=" + winner.evidence + " 最早受影响数据序号=" + winner.seq
                            + " 依据=" + winner.detail)
                    .withLedger(this);
        }

        // 7) 健康路径：全新空目录初始化为 v2；v1 目录原地升级；v2 目录补元数据
        boolean ledgerEmpty = frames.isEmpty();
        if (legacy) {
            if (ledgerEmpty) {
                // 全新目录（ledger 不存在刚创建或为空）不算“老数据升级”
                Files.createDirectories(checkpointDir);
                writeFormatFile();
                writeCheckpoint(0L, 0L, "");
                commitAnchor(0L, 0L, "");
            } else {
                upgradeFromV1(lastDataSeq, lastPos, lastHash);
            }
        } else {
            if (anchor == null) {
                // format 在、anchor 丢（keys 受信，仅可能是极端崩溃/手工清理）：全链已通过，重建锚点但不隐瞒
                commitAnchor(lastPos, lastDataSeq, lastHash);
                compatibilityNote("anchor.json 缺失，已按全链重放结论重建锚点；本次打开无法检测升级点之前的末尾整删");
            }
            if (crashRecovered) {
                // 崩溃补提交后锚点已到真实尾部；内存尾部状态以重放为准
                lastHash = recomputeTipHash();
            }
            ensureGenesisCheckpoint();
        }
    }

    /**
     * 对文件顺序中的 DATA 序号流做整体结构分析：
     * <ul>
     *   <li>相邻互换 (i, i+1) → REORDERED，最早受影响钉较小序号 i；</li>
     *   <li>序号相对应到位置向前跳变（删中间记录、非相邻重排）→ MIDDLE_FRAME_MISSING，
     *       最早受影响为第一个空缺序号。</li>
     * </ul>
     * HMAC 链本身对任何重排/删除都验签失败，这里只负责给出“更贴近人类语义”的证据分类与定位。
     */
    private void analyzeDataSequenceFlow(List<Long> seqsInFileOrder, List<TamperCandidate> candidates) {
        // 相邻互换：文件中出现 (j, i) 且 j = i+1
        java.util.Set<Long> swapFirsts = new java.util.HashSet<>();
        for (int i = 0; i + 1 < seqsInFileOrder.size(); i++) {
            long a = seqsInFileOrder.get(i);
            long b = seqsInFileOrder.get(i + 1);
            if (a == b + 1L) {
                candidates.add(new TamperCandidate(b, TamperEvidence.REORDERED,
                        "相邻两条 DATA 记录顺序被调换：文件顺序为序号 " + a + " 然后 " + b
                                + "，最早受影响（较小）序号=" + b));
                swapFirsts.add(b);
            }
        }
        // 中间缺失：期望第 k 条 DATA 的序号应为 k（PURGE 不占数据序号）；不符则第一个空缺为 k
        for (int k = 0; k < seqsInFileOrder.size(); k++) {
            long expected = k + 1L;
            long actual = seqsInFileOrder.get(k);
            if (actual != expected) {
                // 若该位置正属于某个相邻互换对，则由 REORDERED 证据负责（不重复报 MIDDLE）
                if (swapFirsts.contains(actual) || swapFirsts.contains(expected)) {
                    continue;
                }
                candidates.add(new TamperCandidate(expected, TamperEvidence.MIDDLE_FRAME_MISSING,
                        "第 " + expected + " 条 DATA 记录的序号位置出现 " + actual
                                + "：序号 " + expected + "（或其后连续记录）缺失/被移位，第一个空缺序号=" + expected));
            }
        }
    }

    /** DATA 帧结构异常分类（内容/链级）；序号流的互换与缺失在 {@link #analyzeDataSequenceFlow} 处理。 */
    private void classifyFrame(List<TamperCandidate> candidates, long reportedSeq,
                               boolean posBad, boolean prevBad, boolean crcBad, boolean hmacBad,
                               JsonNode n, String kind) {
        if (crcBad) {
            candidates.add(new TamperCandidate(reportedSeq, TamperEvidence.CONTENT_ALTERED,
                    "帧 pos=" + n.path("pos").asLong() + " kind=" + kind + " dataSeq=" + reportedSeq
                            + " CRC32 不匹配：密文内容被改动"));
        }
        if (hmacBad) {
            candidates.add(new TamperCandidate(reportedSeq, TamperEvidence.CONTENT_ALTERED,
                    "帧 pos=" + n.path("pos").asLong() + " kind=" + kind + " dataSeq=" + reportedSeq
                            + " HMAC 不匹配：帧内容或哈希链被改动"));
        }
        if (posBad) {
            candidates.add(new TamperCandidate(reportedSeq, TamperEvidence.CHAIN_TAMPERED,
                    "帧物理位置错乱：pos=" + n.path("pos").asLong()));
        }
        if (prevBad) {
            candidates.add(new TamperCandidate(reportedSeq, TamperEvidence.CHAIN_TAMPERED,
                    "帧 pos=" + n.path("pos").asLong() + " 的 prev 指针与前一帧 hash 不一致：链被断开/重排"));
        }
    }

    private void upgradeFromV1(long dataSeq, long pos, String tipHash) throws IOException {
        Files.createDirectories(checkpointDir);
        writeFormatFile();
        writeCheckpoint(0L, 0L, "");
        commitAnchor(pos, dataSeq, tipHash);
        List<String> caps = List.of(
                "全链重放已通过：所有现存帧的 HMAC/CRC/序号连续性均验证成功",
                "从本次升级提交点起：末尾整删/半条收尾/来源不明尾部帧检测生效（anchor.json）",
                "新追加记录继续支持加密擦除与 EXPIRY/COMPLIANCE 清除来源区分",
                "检查点与分段核验从序号 " + dataSeq + " 起逐步具备（每 " + checkpointInterval + " 条一个）");
        List<String> limits = List.of(
                "升级发生之前若账本末尾整条记录已被删除，无历史锚点可比，无法追溯检测；保护范围从升级提交点开始",
                "v1 的 PURGE 帧不含 source/requestId，按 EXPIRY/RETENTION 兼容标注，不补造合规请求标识",
                "v1 时代遗留的尾部半帧按旧版本语义视为崩溃撕裂并截断");
        this.compatibilityReport = new CompatibilityReport(true, "1", caps, limits);
    }

    private void ensureGenesisCheckpoint() throws IOException {
        Files.createDirectories(checkpointDir);
        if (readCheckpoint(0L) == null) {
            writeCheckpoint(0L, 0L, "");
        }
    }

    private void compatibilityNote(String note) {
        if (compatibilityReport == null) {
            compatibilityReport = new CompatibilityReport(false, "2", List.of(), List.of(note));
        }
    }

    private void maybeWriteCheckpoint(long dataSeq, long pos, String hash) {
        if (dataSeq % checkpointInterval == 0L) {
            try {
                writeCheckpoint(dataSeq, pos, hash);
            } catch (IOException e) {
                throw new IllegalStateException("检查点写入失败", e);
            }
        }
    }

    // ----------------------------------------------------- verification core

    private VerifyResult verifyFrames(List<Frame> segment, long seedPos, String seedHash, long toDataSeq,
                                      int totalSnapshotFrames, boolean fromCheckpoint,
                                      boolean fullScan, Anchor anchor) {
        List<TamperCandidate> cands = new ArrayList<>();
        String prev = seedHash == null ? "" : seedHash;
        long expectedPos = seedPos;
        long dataCount = seedPos == 0L ? 0L : countDataUpToPos(seedPos);
        for (Frame f : segment) {
            JsonNode n = f.node;
            expectedPos++;
            long pos = n.path("pos").asLong();
            String kind = n.path("kind").asText();
            boolean posBad = pos != expectedPos;
            boolean prevBad = !prev.equals(n.path("prev").asText());
            long reported;
            String recomputed;
            boolean crcBad = false;
            boolean seqGap = false;
            if ("DATA".equals(kind)) {
                long seq = n.path("seq").asLong();
                reported = seq;
                String body = n.path("body").asText();
                boolean dv1 = !n.has("eventTime");
                recomputed = dv1
                        ? hmac(frameDataStringV1(seq, n.path("key").asText(),
                                n.path("stored").asLong(), body, n.path("crc").asLong(), pos, prev))
                        : hmac(frameDataString(seq, n.path("key").asText(),
                                n.path("stored").asLong(), n.path("eventTime").asLong(0L),
                                body, n.path("crc").asLong(), pos, prev));
                crcBad = crc32(body.getBytes(StandardCharsets.UTF_8)) != n.path("crc").asLong();
                dataCount++;
                seqGap = seq != dataCount;
            } else if ("PURGE".equals(kind)) {
                reported = n.path("dataSeq").asLong();
                boolean v2 = n.has("source");
                recomputed = hmac(purgeFrameString(pos, reported, n.path("source").asText(PurgeSource.EXPIRY.name()),
                        n.path("requestId").asText(null), n.path("reason").asText(""),
                        n.path("stored").asLong(), prev, v2));
            } else {
                reported = dataCount + 1L;
                recomputed = "__UNKNOWN__";
            }
            boolean hmacBad = !recomputed.equals(n.path("hash").asText());
            if (posBad || prevBad || crcBad || seqGap || hmacBad) {
                TamperEvidence ev;
                if ("DATA".equals(kind) && seqGap) {
                    ev = TamperEvidence.MIDDLE_FRAME_MISSING;
                } else if (prevBad || posBad) {
                    ev = TamperEvidence.CHAIN_TAMPERED;
                } else {
                    ev = TamperEvidence.CONTENT_ALTERED;
                }
                cands.add(new TamperCandidate(reported, ev,
                        "分段核验：帧 pos=" + pos + " dataSeq=" + reported + " 验签失败"));
            }
            prev = n.path("hash").asText();
        }
        if (fullScan && anchor != null) {
            long actualData = dataCount; // 段内 DATA 计数（全量从 0 起）
            long actualPos = expectedPos;
            if (actualPos < anchor.pos || actualData < anchor.dataSeq) {
                cands.add(new TamperCandidate(actualData + 1L, TamperEvidence.TAIL_RECORDS_MISSING,
                        "核验时账本比已提交锚点短，第一个空缺数据序号=" + (actualData + 1L)));
            }
        }
        long fromSeq = seedPos == 0L ? 1L : (locateDataSeqAtPos(seedPos) + 1L);
        if (cands.isEmpty()) {
            return VerifyResult.ok(fromSeq, toDataSeq, segment.size(), fromCheckpoint);
        }
        TamperCandidate w = cands.get(0);
        for (TamperCandidate c : cands) {
            if (c.seq < w.seq || (c.seq == w.seq && evidenceRank(c.evidence) < evidenceRank(w.evidence))) {
                w = c;
            }
        }
        return new VerifyResult(false, w.seq, w.evidence, w.detail, fromSeq, toDataSeq,
                segment.size(), fromCheckpoint);
    }

    private long countDataUpToPos(long pos) {
        long c = 0L;
        for (Frame f : frames) {
            if (f.node.path("pos").asLong() <= pos && "DATA".equals(f.node.path("kind").asText())) {
                c++;
            }
        }
        return c;
    }

    private long locateDataSeqAtPos(long pos) {
        long seq = 0L;
        for (Frame f : frames) {
            if (f.node.path("pos").asLong() <= pos && "DATA".equals(f.node.path("kind").asText())) {
                seq = f.node.path("seq").asLong();
            }
        }
        return seq;
    }

    private Long locateDataFramePos(List<Frame> snapshot, long dataSeq) {
        for (Frame f : snapshot) {
            if ("DATA".equals(f.node.path("kind").asText()) && f.node.path("seq").asLong() == dataSeq) {
                return f.node.path("pos").asLong();
            }
        }
        return null;
    }

    private Frame frameForPos(List<Frame> fs, long pos) {
        for (Frame f : frames) {
            if (f.node.path("pos").asLong() == pos) {
                return f;
            }
        }
        return null;
    }

    private String recomputeTipHash() {
        return frames.isEmpty() ? "" : frames.get(frames.size() - 1).node.path("hash").asText();
    }

    // ------------------------------------------------------------ meta files

    private record Anchor(long pos, long dataSeq, String hash) {
    }

    private record PurgeMark(PurgeSource source, String requestId, String reason, long storedAt, boolean v2) {
    }

    private record TamperCandidate(long seq, TamperEvidence evidence, String detail) {
    }

    private void writeIntent(String op, long seq, long pos, String source, String requestId, String reason)
            throws IOException {
        long ts = System.currentTimeMillis();
        String canon = "INTENT|" + op + "|" + seq + "|" + pos + "|" + nullToEmpty(source) + "|"
                + nullToEmpty(requestId) + "|" + nullToEmpty(reason) + "|" + ts;
        ObjectNode n = MAPPER.createObjectNode();
        n.put("op", op);
        n.put("seq", seq);
        n.put("pos", pos);
        n.put("source", nullToEmpty(source));
        if (requestId != null) {
            n.put("requestId", requestId);
        }
        n.put("reason", nullToEmpty(reason));
        n.put("ts", ts);
        n.put("sig", hmac(canon));
        atomicMeta(intentFile, n);
    }

    private void deleteIntent() {
        try {
            Files.deleteIfExists(intentFile);
        } catch (IOException ignore) {
            // 意图只用于崩溃仲裁；残留意图在下个意图写入前由重启清理路径处理
        }
    }

    private void rollbackIntent(ObjectNode intent) throws IOException {
        String op = intent.path("op").asText();
        long seq = intent.path("seq").asLong();
        if ("APPEND".equals(op) && frameForPos(frames, intent.path("pos").asLong()) == null) {
            Files.deleteIfExists(keyFile(seq));
        }
        deleteIntent();
    }

    private ObjectNode readIntentOrNull() {
        try {
            if (!Files.exists(intentFile)) {
                return null;
            }
            JsonNode n = MAPPER.readTree(Files.readAllBytes(intentFile));
            String op = n.path("op").asText();
            long ts = n.path("ts").asLong();
            String canon = "INTENT|" + op + "|" + n.path("seq").asLong() + "|" + n.path("pos").asLong()
                    + "|" + n.path("source").asText("") + "|" + n.path("requestId").asText("") + "|"
                    + n.path("reason").asText("") + "|" + ts;
            if (!hmac(canon).equals(n.path("sig").asText())) {
                return null; // 签名不符不可信，按“无合法意图”处理（后续按破坏规则判定）
            }
            return (ObjectNode) n;
        } catch (Exception e) {
            return null;
        }
    }

    private void commitAnchor(long pos, long dataSeq, String hash) throws IOException {
        long ts = System.currentTimeMillis();
        ObjectNode n = MAPPER.createObjectNode();
        n.put("pos", pos);
        n.put("seq", dataSeq);
        n.put("hash", hash);
        n.put("updatedAt", ts);
        n.put("sig", hmac("ANCHOR|" + pos + "|" + dataSeq + "|" + nullToEmpty(hash) + "|" + ts));
        atomicMeta(anchorFile, n);
    }

    private Anchor readAnchorOrNull() {
        try {
            if (!Files.exists(anchorFile)) {
                return null;
            }
            JsonNode n = MAPPER.readTree(Files.readAllBytes(anchorFile));
            long pos = n.path("pos").asLong();
            long seq = n.path("seq").asLong();
            String hash = n.path("hash").asText("");
            long ts = n.path("updatedAt").asLong();
            if (!hmac("ANCHOR|" + pos + "|" + seq + "|" + hash + "|" + ts).equals(n.path("sig").asText())) {
                throw new IllegalStateException("anchor.json 签名校验失败：元数据不可信");
            }
            return new Anchor(pos, seq, hash);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            return null;
        }
    }

    private void writeFormatFile() throws IOException {
        ObjectNode n = MAPPER.createObjectNode();
        n.put("version", FORMAT_VERSION);
        n.put("sig", hmac("FORMAT|" + FORMAT_VERSION));
        atomicMeta(formatFile, n);
    }

    private void writeCheckpoint(long dataSeq, long pos, String hash) throws IOException {
        Files.createDirectories(checkpointDir);
        long ts = System.currentTimeMillis();
        ObjectNode n = MAPPER.createObjectNode();
        n.put("seq", dataSeq);
        n.put("pos", pos);
        n.put("hash", nullToEmpty(hash));
        n.put("createdAt", ts);
        n.put("sig", hmac("CHECKPOINT|" + dataSeq + "|" + pos + "|" + nullToEmpty(hash) + "|" + ts));
        atomicMeta(checkpointDir.resolve("cp-" + dataSeq + ".json"), n);
    }

    private ObjectNode readCheckpoint(long dataSeq) {
        try {
            Path f = checkpointDir.resolve("cp-" + dataSeq + ".json");
            if (!Files.exists(f)) {
                return null;
            }
            JsonNode n = MAPPER.readTree(Files.readAllBytes(f));
            long pos = n.path("pos").asLong();
            String hash = n.path("hash").asText("");
            long ts = n.path("createdAt").asLong();
            if (!hmac("CHECKPOINT|" + dataSeq + "|" + pos + "|" + hash + "|" + ts)
                    .equals(n.path("sig").asText())) {
                throw new IllegalStateException("检查点 " + dataSeq + " 签名校验失败");
            }
            return (ObjectNode) n;
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            return null;
        }
    }

    /** 新鲜目录（空账本）首次初始化 v2 元数据，在 recover 判定为空时由构造路径使用。 */

    private void atomicMeta(Path target, ObjectNode n) throws IOException {
        byte[] bytes = (MAPPER.writeValueAsString(n) + "\n").getBytes(StandardCharsets.UTF_8);
        Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
        try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            ch.write(ByteBuffer.wrap(bytes));
            ch.force(true);
        }
        try {
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException atomicFail) {
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
        }
        try (FileChannel dir = FileChannel.open(target.toAbsolutePath().getParent())) {
            dir.force(true);
        } catch (IOException ignore) {
            // 某些平台不支持目录 fsync
        }
    }

    // ------------------------------------------------------------ internals

    /** 同一序号上多种证据并存时的可解释优先级（数字小者优先报告）。 */
    private static int evidenceRank(TamperEvidence e) {
        return switch (e) {
            case REORDERED -> 0;
            case MIDDLE_FRAME_MISSING -> 1;
            case TAIL_RECORDS_MISSING -> 2;
            case HALF_FRAME_TAIL -> 3;
            case UNEXPECTED_TAIL_FRAME -> 4;
            case CHAIN_TAMPERED -> 5;
            case CONTENT_ALTERED -> 6;
            case OK -> 99;
        };
    }

    private void ensureOpen(String action) {
        if (closed) {
            throw new TamperException(firstTampered,
                    "账本已因检测到破坏而关闭(证据=" + evidence + ",最早受影响序号=" + firstTampered
                            + ")，" + action);
        }
    }

    private void truncateAfterCompleteFrames(byte[] rawBytes, List<String> completeLines) throws IOException {
        long keep = 0L;
        int counted = 0;
        for (int i = 0; i < rawBytes.length && counted < completeLines.size(); i++) {
            if (rawBytes[i] == (byte) '\n') {
                keep = i + 1L;
                counted++;
            }
        }
        try (FileChannel ch = FileChannel.open(ledgerFile, StandardOpenOption.WRITE)) {
            ch.truncate(keep);
            ch.force(true);
        }
    }

    private long guessPartialDataSeq(String partial, long fallback) {
        try {
            JsonNode n = MAPPER.readTree(partial);
            if (n != null && n.has("seq")) {
                return n.path("seq").asLong(fallback);
            }
        } catch (Exception ignore) {
            // 半帧通常无法解析，回退为“下一应到序号”
        }
        return fallback;
    }

    /**
     * 判断无换行的尾部片段是否“长得像帧”：以 { 开头，或带有任意帧特征字段
     * （pos/kind/hash/body/dataSeq/seq/stored/prev）。
     * 真帧写了一半（被 kill 在 force 之前）可能只写出前半段字段；
     * 与帧无关的杂散字节（如 GARBAGE_HALF_FR）不带任何帧特征，仍按崩溃脏字节处理。
     * 这是“无法 100% 区分磁盘脏字节与攻击”的务实启发式：无合法写入意图时，
     * 凡可识别为帧片段的一律从严判破坏。
     */
    private static boolean looksLikeFrameFragment(String partial) {
        String s = partial.stripLeading();
        if (s.startsWith("{")) {
            return true;
        }
        return s.contains("\"pos\"") || s.contains("\"kind\"") || s.contains("\"hash\"")
                || s.contains("\"body\"") || s.contains("\"dataSeq\"") || s.contains("\"seq\"")
                || s.contains("\"stored\"") || s.contains("\"prev\"");
    }

    private void writeFrame(ObjectNode frame) throws IOException {
        byte[] bytes = (MAPPER.writeValueAsString(frame) + "\n").getBytes(StandardCharsets.UTF_8);
        try (FileChannel ch = FileChannel.open(ledgerFile,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                StandardOpenOption.APPEND)) {
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

    /** v1 DATA 帧 HMAC 输入：不含 eventTime（用于老数据目录平滑升级时重放验签）。 */
    private static String frameDataStringV1(long seq, String idemKey, long stored,
                                            String bodyB64, long crc, long pos, String prevHash) {
        return pos + "|DATA|" + seq + "|" + idemKey + "|" + stored + "|"
                + bodyB64 + "|" + crc + "|" + nullToEmpty(prevHash);
    }

    /** PURGE 帧 HMAC 输入：v2 带 source/requestId；v1 老帧沿用旧串保证老链可验。 */
    private static String purgeFrameString(long pos, long seq, String source, String requestId,
                                           String reason, long stored, String prevHash, boolean v2) {
        if (v2) {
            return pos + "|PURGE|" + seq + "|" + nullToEmpty(source) + "|" + nullToEmpty(requestId)
                    + "|" + nullToEmpty(reason) + "|" + stored + "|" + nullToEmpty(prevHash);
        }
        return pos + "|PURGE|" + seq + "|" + nullToEmpty(reason) + "|" + stored + "|"
                + nullToEmpty(prevHash);
    }

    private static PurgeSource parseSource(String s) {
        try {
            return PurgeSource.valueOf(s);
        } catch (Exception e) {
            return PurgeSource.EXPIRY;
        }
    }

    private static long crc32(byte[] bytes) {
        CRC32 crc = new CRC32();
        crc.update(bytes);
        return crc.getValue();
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private record Snapshot(List<Frame> frames, long lastDataSeq, long lastPos, boolean closed, Anchor anchor) {
    }

    private static final class Frame {
        final JsonNode node;
        volatile StoredEvent event;

        Frame(JsonNode node, StoredEvent event) {
            this.node = node;
            this.event = event;
        }
    }
}
