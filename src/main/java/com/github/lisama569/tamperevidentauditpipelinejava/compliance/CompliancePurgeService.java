package com.github.lisama569.tamperevidentauditpipelinejava.compliance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.PurgeMark;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.StoredEvent;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.LegalHoldService;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Logger;

/**
 * 主动合规清除：可预演、可执行、可解释、幂等。
 *
 * <p>优先级（与需求一致，逐条记录给出结论）：
 * <ol>
 *   <li><b>法律保留最高</b>：命中 hold 的记录一律挡下（BLOCKED_BY_LEGAL_HOLD），任何来源都不能清。</li>
 *   <li><b>已清除不重复处理</b>：purged=true 的记录只回报历史来源（ALREADY_PURGED）。</li>
 *   <li><b>合规清除高于保留到期</b>：命中选择器、未被 hold 的记录，无论是否快到期一律按合规清除处理。</li>
 * </ol>
 *
 * <p>幂等：正式执行的请求在 compliance-requests.log 落一条 REQ 帧（请求指纹）与一条 RESULT 帧
 * （完整结论 JSON）。相同 requestId 重放时先比对指纹，指纹一致直接回放 RESULT，不再触碰任何留存内容；
 * 指纹不一致抛 {@link DuplicatePurgeRequestException}。预演不落任何记录，也不产生清除动作。
 */
public class CompliancePurgeService {

    private static final Logger LOG = Logger.getLogger(CompliancePurgeService.class.getName());
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AppendOnlyLedger ledger;
    private final LegalHoldService holds;
    private final Path requestLog;

    /** requestId -> 已执行请求的指纹 */
    private final Map<String, String> fingerprints = new TreeMap<>();
    /** requestId -> 首次执行结果（JSON 原文，回放时原样反序列化） */
    private final Map<String, String> resultJson = new TreeMap<>();

    public CompliancePurgeService(AppendOnlyLedger ledger, LegalHoldService holds, Path requestLog) {
        this.ledger = ledger;
        this.holds = holds;
        this.requestLog = requestLog;
        replayRequestLog();
    }

    public synchronized CompliancePurgeResult submit(CompliancePurgeRequest req) {
        validate(req);
        String fingerprint = fingerprint(req);
        if (fingerprints.containsKey(req.requestId())) {
            if (!fingerprints.get(req.requestId()).equals(fingerprint)) {
                throw new DuplicatePurgeRequestException(req.requestId(),
                        "requestId=" + req.requestId() + " 已用于不同的清除请求，幂等键冲突");
            }
            CompliancePurgeResult first = readStoredResult(req.requestId());
            if (first == null) {
                // 崩溃窗口：REQ 指纹已落盘、RESULT 未写完（PURGE 帧已在链中）。
                // 重新评估只会看到 ALREADY_PURGED，不会二次清除；将其固化为幂等完成结论。
                CompliancePurgeResult recovered = evaluate(req, false);
                CompliancePurgeResult replay = new CompliancePurgeResult(req.requestId(), req.reason(),
                        false, true, recovered.evaluatedAtMs(), recovered.selector(), recovered.items(),
                        recovered.purgedSequences(), recovered.blockedByLegalHold(),
                        recovered.alreadyPurgedSequences());
                persistResultOnly(req.requestId(), replay);
                LOG.warning(() -> "[COMPLIANCE] 恢复未完成的幂等记录 requestId=" + req.requestId()
                        + "（PURGE 已落链，结论固化，无重复清除）");
                return replay;
            }
            CompliancePurgeResult replay = new CompliancePurgeResult(first.requestId(), first.reason(),
                    req.dryRun(), true, first.evaluatedAtMs(), first.selector(), first.items(),
                    first.purgedSequences(), first.blockedByLegalHold(), first.alreadyPurgedSequences());
            LOG.info(() -> "[COMPLIANCE] 幂等重放 requestId=" + req.requestId()
                    + " 清除=" + first.purgedSequences() + " 挡下=" + first.blockedByLegalHold()
                    + " 未再执行任何清除");
            return replay;
        }

        // 预演与任何幂等状态无关：直接评估返回，绝不落盘
        if (req.dryRun()) {
            CompliancePurgeResult previewResult = evaluate(req, true);
            LOG.info(() -> "[COMPLIANCE] 预演 requestId=" + req.requestId()
                    + " 选择器=" + previewResult.selector()
                    + " 将清除=" + previewResult.purgedSequences()
                    + " 法律保留挡下=" + previewResult.blockedByLegalHold());
            return previewResult;
        }

        // 先落 REQ 指纹再执行清除：保证崩溃在“PURGE 已落链、结果未写”之间时，重开仍走幂等恢复而非重复执行
        persistRequestOnly(req, fingerprint);
        CompliancePurgeResult result = evaluate(req, false);
        persistResultOnly(req.requestId(), result);
        LOG.info(() -> "[COMPLIANCE] 执行 requestId=" + req.requestId()
                + " 选择器=" + result.selector()
                + " 清除=" + result.purgedSequences()
                + " 法律保留挡下=" + result.blockedByLegalHold()
                + " 已清除跳过=" + result.alreadyPurgedSequences());
        return result;
    }

    /** 纯预演：与正式执行共用判定逻辑，但绝不改动任何留存内容、不写幂等记录。 */
    public synchronized CompliancePurgeResult preview(CompliancePurgeRequest req) {
        validate(req);
        return evaluate(new CompliancePurgeRequest(req.requestId(), req.reason(), req.subjectPattern(),
                req.fromSeqInclusive(), req.toSeqInclusive(), true), true);
    }

    // ------------------------------------------------------------ decision

    private CompliancePurgeResult evaluate(CompliancePurgeRequest req, boolean previewMode) {
        if (ledger.isClosed()) {
            throw new com.github.lisama569.tamperevidentauditpipelinejava.ledger.TamperException(
                    ledger.firstTamperedSequence(),
                    "账本已因破坏关闭(最早受影响序号=" + ledger.firstTamperedSequence()
                            + ")，拒绝合规清除");
        }
        long evaluatedAt = System.currentTimeMillis();
        List<PurgeItemOutcome> items = new ArrayList<>();
        List<Long> purged = new ArrayList<>();
        List<Long> blocked = new ArrayList<>();
        List<Long> already = new ArrayList<>();

        List<StoredEvent> events;
        synchronized (ledger) {
            events = ledger.all();
        }
        for (StoredEvent e : events) {
            if (!matchesSelector(e, req)) {
                continue;
            }
            long seq = e.sequence();
            // 1) 法律保留最高：已清除的记录无需再判 hold；未清除且命中 hold 一律挡下
            if (!e.purged() && holds.isHeld(e)) {
                blocked.add(seq);
                items.add(PurgeItemOutcome.blocked(seq, "命中法律保留，最高优先级，禁止清除"));
                continue;
            }
            // 2) 已清除：不重复处理，回报历史来源
            if (e.purged()) {
                PurgeMark mark = ledger.purgeMark(seq).orElse(null);
                String src = mark == null ? "RETENTION" : mark.source();
                String rid = mark == null ? null : mark.requestId();
                already.add(seq);
                items.add(PurgeItemOutcome.alreadyPurged(seq, src, rid));
                continue;
            }
            // 3) 合规清除高于到期：命中即按 COMPLIANCE 清
            if (previewMode) {
                purged.add(seq);
                items.add(PurgeItemOutcome.purge(seq, req.requestId()));
            } else {
                synchronized (ledger) {
                    ledger.markPurged(seq, PurgeMark.SOURCE_COMPLIANCE, req.requestId(),
                            req.reason() == null ? "" : req.reason());
                }
                purged.add(seq);
                items.add(PurgeItemOutcome.purge(seq, req.requestId()));
            }
        }
        return new CompliancePurgeResult(req.requestId(), req.reason(), previewMode, false,
                evaluatedAt, selectorText(req), items, purged, blocked, already);
    }

    private boolean matchesSelector(StoredEvent e, CompliancePurgeRequest req) {
        boolean rangeOk = true;
        if (req.hasRangeSelector()) {
            long seq = e.sequence();
            rangeOk = (req.fromSeqInclusive() == null || seq >= req.fromSeqInclusive())
                    && (req.toSeqInclusive() == null || seq <= req.toSeqInclusive());
        }
        if (!rangeOk) {
            return false;
        }
        if (req.hasSubjectSelector()) {
            String payload = ledger.payloadAt(e.sequence());
            if (payload == null) {
                return false; // 已清除记录无 subject 可匹配
            }
            String subject = extractSubject(payload);
            return subject != null && subject.contains(req.subjectPattern());
        }
        // 至少要有一个选择器（validate 已保证），走到这里说明只用了范围
        return req.hasRangeSelector();
    }

    private static String extractSubject(String payloadJson) {
        try {
            JsonNode n = MAPPER.readTree(payloadJson);
            JsonNode s = n.get("subject");
            return s != null && s.isTextual() ? s.asText() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String selectorText(CompliancePurgeRequest req) {
        StringBuilder sb = new StringBuilder();
        if (req.hasSubjectSelector()) {
            sb.append("subject~=").append(req.subjectPattern());
        }
        if (req.hasRangeSelector()) {
            if (sb.length() > 0) {
                sb.append(';');
            }
            sb.append("seq[").append(req.fromSeqInclusive() == null ? "*" : req.fromSeqInclusive())
                    .append(',').append(req.toSeqInclusive() == null ? "*" : req.toSeqInclusive())
                    .append(']');
        }
        return sb.toString();
    }

    private void validate(CompliancePurgeRequest req) {
        if (req == null || req.requestId() == null || req.requestId().isBlank()) {
            throw new IllegalArgumentException("requestId 不能为空");
        }
        if (req.reason() == null || req.reason().isBlank()) {
            throw new IllegalArgumentException("合规清除必须提供 reason");
        }
        if (!req.hasSubjectSelector() && !req.hasRangeSelector()) {
            throw new IllegalArgumentException("必须提供 subjectPattern 或序号范围中的至少一个选择器");
        }
        if (req.fromSeqInclusive() != null && req.toSeqInclusive() != null
                && req.fromSeqInclusive() > req.toSeqInclusive()) {
            throw new IllegalArgumentException("序号范围非法：from > to");
        }
    }

    // ------------------------------------------------------------ idempotency log

    private String fingerprint(CompliancePurgeRequest req) {
        String raw = req.requestId() + "|" + req.reason() + "|" + nullSafe(req.subjectPattern())
                + "|" + req.fromSeqInclusive() + "|" + req.toSeqInclusive();
        return Integer.toHexString(raw.hashCode());
    }

    private static String nullSafe(String s) {
        return s == null ? "" : s;
    }

    private CompliancePurgeResult readStoredResult(String requestId) {
        String json = resultJson.get(requestId);
        if (json == null) {
            return null;
        }
        try {
            return MAPPER.readValue(json, CompliancePurgeResult.class);
        } catch (IOException e) {
            throw new IllegalStateException("无法读取已存清除结果: " + requestId, e);
        }
    }

    /** 执行前先落 REQ 指纹（崩溃恢复据此识别“进行中但 PURGE 已落链”的请求）。 */
    private void persistRequestOnly(CompliancePurgeRequest req, String fingerprint) {
        ObjectNode reqNode = MAPPER.createObjectNode();
        reqNode.put("op", "REQ");
        reqNode.put("requestId", req.requestId());
        reqNode.put("fingerprint", fingerprint);
        reqNode.put("reason", req.reason());
        reqNode.put("subjectPattern", req.subjectPattern());
        reqNode.putPOJO("from", req.fromSeqInclusive());
        reqNode.putPOJO("to", req.toSeqInclusive());
        reqNode.put("stored", System.currentTimeMillis());
        appendLine(reqNode.toString());
        fingerprints.put(req.requestId(), fingerprint);
    }

    /** 执行后落 RESULT 完整结论（重放时原样回放）。 */
    private void persistResultOnly(String requestId, CompliancePurgeResult result) {
        try {
            ObjectNode resNode = MAPPER.createObjectNode();
            resNode.put("op", "RESULT");
            resNode.put("requestId", requestId);
            resNode.set("result", MAPPER.valueToTree(result));
            appendLine(resNode.toString());
            resultJson.put(requestId, MAPPER.writeValueAsString(result));
        } catch (IOException e) {
            throw new IllegalStateException("合规清除结果日志写入失败: " + e.getMessage(), e);
        }
    }

    private void replayRequestLog() {
        try {
            if (!Files.exists(requestLog)) {
                Files.createDirectories(requestLog.toAbsolutePath().getParent());
                Files.createFile(requestLog);
                return;
            }
            for (String line : Files.readAllLines(requestLog, StandardCharsets.UTF_8)) {
                if (line.isBlank()) {
                    continue;
                }
                JsonNode n = MAPPER.readTree(line);
                String op = n.path("op").asText();
                String rid = n.path("requestId").asText();
                if ("REQ".equals(op)) {
                    fingerprints.put(rid, n.path("fingerprint").asText());
                } else if ("RESULT".equals(op)) {
                    resultJson.put(rid, n.path("result").toString());
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("无法初始化合规清除请求日志: " + requestLog, e);
        }
    }

    private void appendLine(String line) {
        byte[] bytes = (line + "\n").getBytes(StandardCharsets.UTF_8);
        try (FileChannel ch = FileChannel.open(requestLog, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            ch.write(ByteBuffer.wrap(bytes));
            ch.force(true);
        } catch (IOException e) {
            throw new IllegalStateException("合规请求日志写入失败", e);
        }
    }
}
