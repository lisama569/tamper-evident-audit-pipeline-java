package com.github.lisama569.tamperevidentauditpipelinejava.compliance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 合规清除请求/结论日志（purge-requests.log，逐行 JSON，force 落盘，重启重放）。
 *
 * <p>作用：让“同一 requestId 重复提交返回与首次一致的结论”不依赖运行期内存。
 * <ul>
 *   <li>REQUEST 行：请求参数（选择器、原因、预演标记）；同 id 参数不一致 → {@link DuplicatePurgeRequestException}。</li>
 *   <li>RESULT 行：首次执行的最终结论（每条记录的决策与依据）；重放请求直接返回该结论，不再执行任何清除。</li>
 * </ul>
 * 预演请求同样留痕：同一 requestId 的第二次预演返回完全相同的结论（由账本状态纯函数重算，
 * 且结论一致性通过决策清单比对保证）。
 */
public class PurgeRequestStore {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Path file;
    private final Map<String, RecordedRequest> requests = new LinkedHashMap<>();
    private final Map<String, CompliancePurgeResult> results = new LinkedHashMap<>();

    public PurgeRequestStore(Path logFile) {
        this.file = logFile;
        try {
            Files.createDirectories(logFile.toAbsolutePath().getParent());
            if (!Files.exists(logFile)) {
                Files.createFile(logFile);
            }
            recover();
        } catch (IOException e) {
            throw new IllegalStateException("无法初始化合规清除请求日志: " + logFile, e);
        }
    }

    public synchronized RecordedRequest recordedRequest(String requestId) {
        return requests.get(requestId);
    }

    public synchronized CompliancePurgeResult recordedResult(String requestId) {
        return results.get(requestId);
    }

    /** 首次登记请求并固定评估边界 evalUpToSequence（当时的最大数据序号）。 */
    public synchronized void recordRequest(CompliancePurgeRequest request, long evalUpToSequence) {
        append(toRequestNode(request, evalUpToSequence, System.currentTimeMillis()));
        requests.put(request.requestId(), RecordedRequest.from(request, evalUpToSequence));
    }

    /** 首次操作完成后持久化结论（每条记录的决策、依据与清除来源）；预演/执行分别留痕。 */
    public synchronized void recordResult(CompliancePurgeResult result) {
        String key = resultKey(result.requestId(), result.dryRun());
        if (results.containsKey(key)) {
            return;
        }
        append(toResultNode(result, System.currentTimeMillis()));
        results.put(key, result);
    }

    public synchronized CompliancePurgeResult recordedResult(String requestId, boolean dryRun) {
        return results.get(resultKey(requestId, dryRun));
    }

    private static String resultKey(String requestId, boolean dryRun) {
        return (dryRun ? "PREVIEW:" : "EXECUTE:") + requestId;
    }

    // ------------------------------------------------------------ internals

    private void append(ObjectNode node) {
        byte[] bytes = (node.toString() + "\n").getBytes(StandardCharsets.UTF_8);
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            ch.write(ByteBuffer.wrap(bytes));
            ch.force(true);
        } catch (IOException e) {
            throw new IllegalStateException("合规清除请求日志写入失败", e);
        }
    }

    private void recover() throws IOException {
        byte[] bytes = Files.readAllBytes(file);
        if (bytes.length > 0 && bytes[bytes.length - 1] != (byte) '\n') {
            // 崩溃在写日志途中：截断最后不完整行（请求日志本身只用于幂等，未写完等同于请求未完成）
            int cut = bytes.length - 1;
            while (cut > 0 && bytes[cut] != (byte) '\n') {
                cut--;
            }
            long keep = bytes[cut] == (byte) '\n' ? cut + 1L : 0L;
            try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE)) {
                ch.truncate(keep);
            }
            bytes = Files.readAllBytes(file);
        }
        for (String line : new String(bytes, StandardCharsets.UTF_8).split("\n")) {
            if (line.isBlank()) {
                continue;
            }
            try {
                ObjectNode n = (ObjectNode) MAPPER.readTree(line);
                if ("RESULT".equals(n.path("op").asText())) {
                    boolean dry = n.path("dryRun").asBoolean();
                    results.put(resultKey(n.path("requestId").asText(), dry), resultFromNode(n));
                } else {
                    requests.put(n.path("requestId").asText(), RecordedRequest.fromNode(n));
                }
                // RESULT 行存在时无需特殊处理，上面已入 results
            } catch (Exception e) {
                throw new IOException("合规清除请求日志损坏: " + line, e);
            }
        }
    }

    private ObjectNode toRequestNode(CompliancePurgeRequest r, long evalUpTo, long ts) {
        ObjectNode n = MAPPER.createObjectNode();
        n.put("op", "REQUEST");
        n.put("requestId", r.requestId());
        n.put("reason", r.reason());
        if (r.subject() != null) {
            n.put("subject", r.subject());
        }
        if (r.fromSequence() != null) {
            n.put("fromSequence", r.fromSequence());
        }
        if (r.toSequence() != null) {
            n.put("toSequence", r.toSequence());
        }
        n.put("dryRun", r.dryRun());
        n.put("evalUpToSequence", evalUpTo);
        n.put("ts", ts);
        return n;
    }

    private ObjectNode toResultNode(CompliancePurgeResult r, long ts) {
        ObjectNode n = MAPPER.createObjectNode();
        n.put("op", "RESULT");
        n.put("requestId", r.requestId());
        n.put("reason", r.reason());
        n.put("dryRun", r.dryRun());
        n.put("evaluatedAtMs", r.evaluatedAtMs());
        n.put("selector", r.selector());
        n.put("ts", ts);
        n.set("items", MAPPER.valueToTree(r.items()));
        n.set("purged", MAPPER.valueToTree(r.purgedSequences()));
        n.set("blocked", MAPPER.valueToTree(r.blockedByLegalHold()));
        n.set("alreadyPurged", MAPPER.valueToTree(r.alreadyPurged()));
        n.set("retained", MAPPER.valueToTree(r.retainedSequences()));
        return n;
    }

    private CompliancePurgeResult resultFromNode(ObjectNode n) {
        var items = new java.util.ArrayList<RecordPurgeItem>();
        for (JsonNode it : n.path("items")) {
            items.add(new RecordPurgeItem(it.path("sequence").asLong(),
                    RecordDecision.valueOf(it.path("decision").asText()),
                    it.path("rationale").asText(""),
                    it.path("purgeSource").asText(null)));
        }
        return new CompliancePurgeResult(n.path("requestId").asText(), n.path("reason").asText(""),
                n.path("dryRun").asBoolean(), true, n.path("evaluatedAtMs").asLong(),
                n.path("selector").asText(""), items,
                longs(n.path("purged")), longs(n.path("blocked")),
                longs(n.path("alreadyPurged")), longs(n.path("retained")));
    }

    private static java.util.List<Long> longs(JsonNode arr) {
        java.util.List<Long> out = new java.util.ArrayList<>();
        arr.forEach(x -> out.add(x.asLong()));
        return out;
    }

    /** 已持久化的请求参数指纹与首次评估边界，用于幂等冲突检测。 */
    public record RecordedRequest(String reason, String subject, Long fromSequence,
                                  Long toSequence, boolean dryRun, long evalUpToSequence) {
        static RecordedRequest from(CompliancePurgeRequest r, long evalUpToSequence) {
            return new RecordedRequest(r.reason(), r.subject(), r.fromSequence(), r.toSequence(),
                    r.dryRun(), evalUpToSequence);
        }

        static RecordedRequest fromNode(ObjectNode n) {
            return new RecordedRequest(n.path("reason").asText(""),
                    n.hasNonNull("subject") ? n.path("subject").asText() : null,
                    n.hasNonNull("fromSequence") ? n.path("fromSequence").asLong() : null,
                    n.hasNonNull("toSequence") ? n.path("toSequence").asLong() : null,
                    n.path("dryRun").asBoolean(),
                    n.path("evalUpToSequence").asLong(0L));
        }

        void requireSame(CompliancePurgeRequest r) {
            RecordedRequest other = new RecordedRequest(r.reason(), r.subject(), r.fromSequence(),
                    r.toSequence(), r.dryRun(), evalUpToSequence);
            // 预演(dryRun=true)与执行(dryRun=false)视为同一业务请求的两种操作，不参与冲突判定
            if (!reason().equals(other.reason()) || !java.util.Objects.equals(subject, other.subject)
                    || !java.util.Objects.equals(fromSequence, other.fromSequence)
                    || !java.util.Objects.equals(toSequence, other.toSequence)) {
                throw new DuplicatePurgeRequestException(
                        "合规清除请求标识 " + r.requestId() + " 已提交过，但选择器/原因与首次不一致：首次="
                                + this + " 本次=" + other + "；拒绝执行（幂等冲突）");
            }
        }
    }
}
