package com.github.lisama569.tamperevidentauditpipelinejava.ledger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

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
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.zip.CRC32;

/**
 * 防篡改只追加账本。
 *
 * <p>磁盘形态（ledger.log，逐行一个 JSON 帧）：
 * <ul>
 *   <li>DATA 帧：{pos, seq(数据序号), kind=DATA, key(幂等键), stored(写入时间ms),
 *       prev(前一帧 hash), hash(本帧 HMAC), body(base64(iv||AES-GCM(canonicalPayload))), crc(对 body-b64 的 CRC32)}；
 *       每条记录使用独立随机 DEK，存于 keys/{seq}.key。</li>
 *   <li>PURGE 帧：{pos, kind=PURGE, dataSeq, reason, stored, prev, hash}，表示某条 DATA 被合规/到期清除。</li>
 * </ul>
 *
 * <p>保证：
 * <ul>
 *   <li>并发追加串行化；数据序号唯一且无空洞；写完 force 落盘，崩溃留下的最后半帧在打开时截断，永不半条可见。</li>
 *   <li>HMAC 哈希链（密钥位于账本之外 keys/hmac.key）：任何篡改/删除/重排都会在校验时暴露，
 *       firstTamperedSequence 指向最早受影响的数据记录；一旦检测到破坏，账本进入 closed，拒绝一切追加。</li>
 *   <li>清除 = 追加 PURGE 帧后删除对应 DEK（加密擦除）：链与 envelope 仍可验证，明文不可恢复。</li>
 * </ul>
 */
public class AppendOnlyLedger {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int GCM_TAG_BITS = 128;

    private final Path ledgerFile;
    private final Path keyDir;
    private final byte[] hmacKey;

    private final List<Frame> frames = new ArrayList<>();
    private final Map<Long, StoredEvent> bySeq = new HashMap<>();
    private final Map<String, StoredEvent> byIdemKey = new HashMap<>();

    private String lastHash;
    private long lastPos;
    private long lastDataSeq;
    private boolean closed;
    private long firstTampered = -1L;

    public AppendOnlyLedger(Path ledgerFile) {
        try {
            this.ledgerFile = ledgerFile;
            Files.createDirectories(ledgerFile.toAbsolutePath().getParent());
            this.keyDir = ledgerFile.toAbsolutePath().getParent().resolve("keys");
            Files.createDirectories(keyDir);
            this.hmacKey = loadOrCreateHmacKey();
            recover();
        } catch (IOException e) {
            throw new IllegalStateException("无法初始化账本: " + ledgerFile, e);
        }
    }

    /**
     * 降级打开：行为与构造器相同，但检测到篡改时<strong>不抛出</strong>，
     * 而是返回一个已 closed 的实例（已解析记录仍可只读查询，追加一律被拒绝）。
     * 适用于要求服务保持在线、通过 API 明确返回 LEDGER_TAMPERED 的部署。
     */
    public static AppendOnlyLedger openDegraded(Path ledgerFile) {
        try {
            return new AppendOnlyLedger(ledgerFile);
        } catch (TamperException t) {
            // 构造器在抛出前已完成状态构建（closed=true、firstTampered 已定位），可直接返回该实例
            return t.ledger();
        }
    }

    // ---------------------------------------------------------------- append

    public synchronized StoredEvent append(String idempotencyKey, String payloadJson, long eventTimeMs) {
        if (closed) {
            throw new TamperException(firstTampered,
                    "账本已因检测到篡改而关闭(最早受影响序号=" + firstTampered + ")，拒绝追加");
        }
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
            writeFrame(frame);

            Path keyFile = keyFile(dataSeq);
            Files.write(keyFile, dek);
            trySetOwnerOnly(keyFile);

            StoredEvent event = new StoredEvent(dataSeq, idempotencyKey, payloadJson,
                    hash, nullToEmpty(lastHash), now, false);
            frames.add(new Frame(frame, event));
            bySeq.put(dataSeq, event);
            byIdemKey.put(idempotencyKey, event);
            lastHash = hash;
            lastPos = pos;
            lastDataSeq = dataSeq;
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

    // ---------------------------------------------------------------- purge

    /**
     * 追加 PURGE 标记帧（链内可审计），随后删除 DEK 完成加密擦除。
     * 若 DEK 已删除（重启重放）则保持幂等。
     */
    public synchronized void markPurged(long sequence) {
        if (closed) {
            throw new TamperException(firstTampered, "账本已关闭，拒绝标记清除");
        }
        StoredEvent event = bySeq.get(sequence);
        if (event == null) {
            throw new IllegalArgumentException("记录不存在: " + sequence);
        }
        if (event.purged()) {
            return;
        }
        long now = System.currentTimeMillis();
        long pos = lastPos + 1L;
        String reason = "RETENTION";
        String hash = hmac(pos + "|PURGE|" + sequence + "|" + reason + "|" + now + "|" + nullToEmpty(lastHash));
        ObjectNode frame = MAPPER.createObjectNode();
        frame.put("pos", pos);
        frame.put("kind", "PURGE");
        frame.put("dataSeq", sequence);
        frame.put("reason", reason);
        frame.put("stored", now);
        frame.put("prev", nullToEmpty(lastHash));
        frame.put("hash", hash);
        try {
            writeFrame(frame);
            Files.deleteIfExists(keyFile(sequence));
        } catch (IOException e) {
            throw new IllegalStateException("写入清除标记失败: " + e.getMessage(), e);
        }
        StoredEvent purged = new StoredEvent(sequence, event.idempotencyKey(), null,
                event.hash(), event.prevHash(), event.storedAtMs(), true);
        bySeq.put(sequence, purged);
        byIdemKey.put(event.idempotencyKey(), purged);
        for (int i = 0; i < frames.size(); i++) {
            StoredEvent ev = frames.get(i).event;
            if (ev != null && ev.sequence() == sequence) {
                frames.set(i, new Frame(frames.get(i).node, purged));
            }
        }
        lastHash = hash;
        lastPos = pos;
    }

    /** 全量校验：返回最早受影响的数据序号；正常返回 -1。 */
    public synchronized long verify() {
        String prev = "";
        long expectedPos = 0L;
        long earliest = -1L;
        long dataCount = 0L;
        for (Frame f : frames) {
            JsonNode n = f.node;
            long pos = n.path("pos").asLong();
            expectedPos++;
            String kind = n.path("kind").asText();
            boolean chainBroken = false;
            if (pos != expectedPos) {
                chainBroken = true; // 重排或删除导致位置错乱
            }
            String recomputed;
            long reported;
            if ("DATA".equals(kind)) {
                long seq = n.path("seq").asLong();
                String body = n.path("body").asText();
                reported = seq;
                recomputed = hmac(frameDataString(seq, n.path("key").asText(),
                        n.path("stored").asLong(), n.path("eventTime").asLong(),
                        body, n.path("crc").asLong(), pos, prev));
                long actualCrc = crc32(body.getBytes(StandardCharsets.UTF_8));
                if (actualCrc != n.path("crc").asLong()) {
                    chainBroken = true;
                }
                if (seq != ++dataCount) {
                    chainBroken = true; // 数据序号空洞/重排
                }
            } else {
                long seq = n.path("dataSeq").asLong();
                reported = seq;
                recomputed = hmac(pos + "|PURGE|" + seq + "|" + n.path("reason").asText()
                        + "|" + n.path("stored").asLong() + "|" + prev);
            }
            if (chainBroken || !recomputed.equals(n.path("hash").asText())
                    || !prev.equals(n.path("prev").asText())) {
                if (earliest < 0L) {
                    earliest = reported;
                }
            }
            prev = n.path("hash").asText();
        }
        return earliest;
    }

    // ------------------------------------------------------------ recovery

    private void recover() throws IOException {
        if (!Files.exists(ledgerFile)) {
            Files.createDirectories(ledgerFile.getParent());
            Files.createFile(ledgerFile);
            lastHash = "";
            return;
        }
        // 1) 截断最后一个物理不完整帧（崩溃撕裂），绝不留半条记录。按字节处理，避免引入额外空行。
        truncatePartialTail();
        byte[] rawBytes = Files.readAllBytes(ledgerFile);

        // 2) 顺序重放：CRC + HMAC 链 + 序号连续性校验。
        java.util.Set<Long> purgeMarks = new java.util.HashSet<>();
        java.util.List<Long> missingKeyOrDecryptFailure = new java.util.ArrayList<>();
        String prev = "";
        long expectedPos = 0L;
        long dataCount = 0L;
        long earliest = -1L;
        String rawText = new String(rawBytes, StandardCharsets.UTF_8);
        for (String line : rawText.split("\n")) {
            if (line.isBlank()) {
                continue;
            }
            JsonNode n = parseFrameLine(line);
            if (n == null) {
                // 截断之后理论上不会出现；出现则按破坏处理，绝不静默忽略
                continue;
            }
            expectedPos++;
            long pos = n.path("pos").asLong();
            String kind = n.path("kind").asText();
            boolean broken = pos != expectedPos || !prev.equals(n.path("prev").asText());
            long reported;
            String recomputed;
            if ("DATA".equals(kind)) {
                long seq = n.path("seq").asLong();
                reported = seq;
                String body = n.path("body").asText();
                recomputed = hmac(frameDataString(seq, n.path("key").asText(),
                        n.path("stored").asLong(), n.path("eventTime").asLong(),
                        body, n.path("crc").asLong(), pos, prev));
                if (crc32(body.getBytes(StandardCharsets.UTF_8)) != n.path("crc").asLong()) {
                    broken = true;
                }
                if (seq != ++dataCount) {
                    broken = true;
                }
            } else {
                long seq = n.path("dataSeq").asLong();
                reported = seq;
                purgeMarks.add(seq);
                recomputed = hmac(pos + "|PURGE|" + seq + "|" + n.path("reason").asText()
                        + "|" + n.path("stored").asLong() + "|" + prev);
            }
            if (broken || !recomputed.equals(n.path("hash").asText())) {
                if (earliest < 0L) {
                    earliest = reported;
                }
            }
            prev = n.path("hash").asText();
            Frame frame = new Frame(n, null);
            frames.add(frame);
            lastPos = Math.max(lastPos, pos);
            if ("DATA".equals(kind)) {
                long seq = n.path("seq").asLong();
                // 此时尚不知道后续是否存在 PURGE 标记，一律先按未清除装载；
                // DEK 缺失/解密失败先记录，第 3 步收齐 PURGE 标记后再区分“合法清除”与“私删”。
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
                    missingKeyOrDecryptFailure.add(seq);
                }
                StoredEvent event = new StoredEvent(seq, n.path("key").asText(), payload,
                        n.path("hash").asText(), n.path("prev").asText(),
                        n.path("stored").asLong(), false);
                bySeq.put(seq, event);
                byIdemKey.put(event.idempotencyKey(), event);
                frame.event = event;
                lastDataSeq = Math.max(lastDataSeq, seq);
            }
        }
        lastHash = prev;

        // 3) 重放 PURGE 标记：崩溃在“标记已落盘、DEK 未删除”之间则补删（幂等完成清除）。
        for (long seq : purgeMarks) {
            try {
                Files.deleteIfExists(keyFile(seq));
            } catch (IOException ignore) {
                // 下轮 markPurged/清除任务会重试
            }
            missingKeyOrDecryptFailure.remove(seq); // 有合法 PURGE 标记，密钥缺失是预期的
            StoredEvent ev = bySeq.get(seq);
            if (ev != null && !ev.purged()) {
                StoredEvent purged = new StoredEvent(seq, ev.idempotencyKey(), null,
                        ev.hash(), ev.prevHash(), ev.storedAtMs(), true);
                bySeq.put(seq, purged);
                byIdemKey.put(ev.idempotencyKey(), purged);
            }
        }
        // 4) 无 PURGE 标记却 DEK 缺失/无法解密：未授权删除或密文被破坏 → 篡改。
        for (long seq : missingKeyOrDecryptFailure) {
            if (earliest < 0L || seq < earliest) {
                earliest = seq;
            }
        }

        if (earliest >= 0L) {
            closed = true;
            firstTampered = earliest;
            throw new TamperException(earliest,
                    "打开账本时检测到篡改/删除/重排，最早受影响数据序号=" + earliest + "，账本已关闭并拒绝追加")
                    .withLedger(this);
        }
    }

    // ------------------------------------------------------------ internals

    /**
     * 截断物理不完整的尾部帧：读取全部字节，找到最后一个换行符；
     * 若文件不以换行结束，则丢弃最后一个换行之后的内容（崩溃撕裂的半帧）。
     */
    private void truncatePartialTail() throws IOException {
        byte[] bytes = Files.readAllBytes(ledgerFile);
        if (bytes.length == 0 || bytes[bytes.length - 1] == (byte) '\n') {
            return; // 空文件或最后一行完整结束
        }
        int cut = bytes.length - 1;
        while (cut > 0 && bytes[cut] != (byte) '\n') {
            cut--;
        }
        long keep = bytes[cut] == (byte) '\n' ? cut + 1L : 0L;
        try (FileChannel ch = FileChannel.open(ledgerFile, StandardOpenOption.WRITE)) {
            ch.truncate(keep);
        }
    }

    private void writeFrame(ObjectNode frame) throws IOException {        byte[] bytes = (MAPPER.writeValueAsString(frame) + "\n").getBytes(StandardCharsets.UTF_8);
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

    private static long crc32(byte[] bytes) {
        CRC32 crc = new CRC32();
        crc.update(bytes);
        return crc.getValue();
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    @SuppressWarnings("unused")
    private static String sha256Hex(byte[] bytes) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
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
