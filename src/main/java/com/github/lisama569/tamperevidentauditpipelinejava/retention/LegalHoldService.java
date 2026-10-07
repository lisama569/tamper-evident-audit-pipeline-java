package com.github.lisama569.tamperevidentauditpipelinejava.retention;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.StoredEvent;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 法律保留登记与匹配（holds.log 逐行 JSON，持久化，重启有效）。
 *
 * <p>匹配规则：对记录明文载荷中的 subject 字段做子串匹配（大小写敏感的确定性子串）。
 * 命中任一 hold 的记录在任何情况下都不得被清除。
 */
public class LegalHoldService {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Path file;
    private final Map<String, LegalHold> holds = new LinkedHashMap<>();

    public LegalHoldService(Path holdFile) {
        this.file = holdFile;
        try {
            Files.createDirectories(holdFile.toAbsolutePath().getParent());
            if (!Files.exists(holdFile)) {
                Files.createFile(holdFile);
            }
            for (String line : Files.readAllLines(holdFile, StandardCharsets.UTF_8)) {
                if (line.isBlank()) {
                    continue;
                }
                LegalHold h = fromNode((ObjectNode) MAPPER.readTree(line));
                holds.put(h.holdId(), h);
            }
        } catch (IOException e) {
            throw new IllegalStateException("无法初始化法律保留文件: " + holdFile, e);
        }
    }

    public synchronized LegalHold addHold(String holdId, String subjectPattern, String reason) {
        if (holdId == null || holdId.isBlank()) {
            throw new IllegalArgumentException("holdId 不能为空");
        }
        if (holds.containsKey(holdId)) {
            throw new IllegalArgumentException("法律保留已存在: " + holdId);
        }
        LegalHold hold = new LegalHold(holdId, subjectPattern, reason, System.currentTimeMillis());
        append(toNode(hold));
        holds.put(holdId, hold);
        return hold;
    }

    public synchronized boolean removeHold(String holdId) {
        LegalHold removed = holds.remove(holdId);
        if (removed == null) {
            return false;
        }
        append(removalNode(holdId));
        return true;
    }

    public synchronized List<LegalHold> holds() {
        return new ArrayList<>(holds.values());
    }

    /**
     * 判断记录是否处于法律保留之下。
     * 已清除记录（无明文）只按其 envelope 无法匹配 subject；但清除策略会先于清除检查 hold，
     * 已处于 hold 的记录根本不会进入清除流程。
     */
    public boolean isHeld(StoredEvent event) {
        if (event == null || event.payloadJson() == null) {
            return false;
        }
        String subject = extractSubject(event.payloadJson());
        if (subject == null) {
            return false;
        }
        List<LegalHold> snapshot;
        synchronized (this) {
            snapshot = holds();
        }
        for (LegalHold hold : snapshot) {
            if (hold.subjectPattern() != null && !hold.subjectPattern().isEmpty()
                    && subject.contains(hold.subjectPattern())) {
                return true;
            }
        }
        return false;
    }

    static String extractSubject(String payloadJson) {
        return subjectOf(payloadJson);
    }

    /** 从归一化载荷中提取 subject（供保留/合规清除共用，保证匹配口径一致）。 */
    public static String subjectOf(String payloadJson) {
        try {
            JsonNode n = MAPPER.readTree(payloadJson);
            JsonNode s = n.get("subject");
            return s != null && s.isTextual() ? s.asText() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private void append(ObjectNode node) {
        byte[] bytes = (node.toString() + "\n").getBytes(StandardCharsets.UTF_8);
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            ch.write(ByteBuffer.wrap(bytes));
            ch.force(true);
        } catch (IOException e) {
            throw new IllegalStateException("holds 写入失败", e);
        }
    }

    private ObjectNode toNode(LegalHold h) {
        ObjectNode n = MAPPER.createObjectNode();
        n.put("op", "ADD");
        n.put("holdId", h.holdId());
        n.put("pattern", h.subjectPattern());
        n.put("reason", h.reason());
        n.put("createdAt", h.createdAtMs());
        return n;
    }

    private ObjectNode removalNode(String holdId) {
        ObjectNode n = MAPPER.createObjectNode();
        n.put("op", "REMOVE");
        n.put("holdId", holdId);
        n.put("createdAt", System.currentTimeMillis());
        return n;
    }

    private LegalHold fromNode(ObjectNode n) {
        String op = n.path("op").asText("ADD");
        String holdId = n.path("holdId").asText();
        if ("REMOVE".equals(op)) {
            holds.remove(holdId);
            return null;
        }
        return new LegalHold(holdId, n.path("pattern").asText(""),
                n.path("reason").asText(""), n.path("createdAt").asLong());
    }
}
