package com.github.lisama569.tamperevidentauditpipelinejava.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.CompliancePurgeRequest;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.CompliancePurgeResult;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.VerifyResult;
import com.github.lisama569.tamperevidentauditpipelinejava.model.IngestResult;
import com.github.lisama569.tamperevidentauditpipelinejava.model.RejectReason;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.LegalHold;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.PurgeResult;
import com.github.lisama569.tamperevidentauditpipelinejava.service.AuditPipelineService;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * HTTP 接口：事件接入、保留清除、法律保留管理。
 */
@RestController
@RequestMapping("/audit")
public class AuditController {

    private final AuditPipelineService service;

    public AuditController(AuditPipelineService service) {
        this.service = service;
    }

    @PostMapping("/events")
    public ResponseEntity<Map<String, Object>> ingest(@RequestBody JsonNode body) {
        IngestResult result = service.ingest(body);
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("accepted", result.accepted());
        view.put("duplicate", result.duplicate());
        view.put("sequence", result.sequence());
        view.put("idempotencyKey", result.idempotencyKey());
        view.put("reason", result.reason() == null ? null : result.reason().name());
        view.put("detail", result.detail());
        if (result.accepted()) {
            return ResponseEntity.ok(view);
        }
        HttpStatus status = result.reason() == RejectReason.LEDGER_TAMPERED
                ? HttpStatus.SERVICE_UNAVAILABLE : HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(status).body(view);
    }

    @PostMapping("/retention/enforce")
    public PurgeResult enforce() {
        return service.enforceRetention();
    }

    /**
     * 主动合规清除。body：{requestId, reason, subjectPattern?, fromSeqInclusive?, toSeqInclusive?, dryRun?}。
     * dryRun=true 为预演（不改任何留存内容）；同一 requestId 重复提交回放首次结论（idempotentReplay=true）。
     */
    @PostMapping("/compliance/purges")
    public CompliancePurgeResult compliancePurge(@RequestBody Map<String, Object> body) {
        CompliancePurgeRequest req = new CompliancePurgeRequest(
                str(body.get("requestId")),
                str(body.get("reason")),
                str(body.get("subjectPattern")),
                lng(body.get("fromSeqInclusive")),
                lng(body.get("toSeqInclusive")),
                Boolean.TRUE.equals(body.get("dryRun")));
        return service.compliancePurge(req);
    }

    /** 全量完整性核验；healthy=false 时 firstTamperedSequence 给出最早受影响序号。 */
    @PostMapping("/verify")
    public Map<String, Object> verify(@RequestBody(required = false) Map<String, Object> body) {
        Map<String, Object> view = new LinkedHashMap<>();
        if (body != null && (body.containsKey("fromSeqInclusive") || body.containsKey("toSeqInclusive"))) {
            long from = body.get("fromSeqInclusive") == null ? 1L
                    : ((Number) body.get("fromSeqInclusive")).longValue();
            long to = body.get("toSeqInclusive") == null ? service.ledger().nextSequence() - 1
                    : ((Number) body.get("toSeqInclusive")).longValue();
            VerifyResult r = service.verifyRange(from, to);
            view.put("healthy", r.healthy());
            view.put("firstTamperedSequence", r.firstTamperedSequence());
            view.put("fromSeqInclusive", r.fromSeqInclusive());
            view.put("toSeqInclusive", r.toSeqInclusive());
            view.put("framesChecked", r.framesChecked());
            view.put("anchoredAfterDataSeq", r.anchoredAfterDataSeq());
            view.put("basis", r.basis());
        } else {
            long first = service.verifyLedger();
            view.put("healthy", first < 0);
            view.put("firstTamperedSequence", first);
        }
        return view;
    }

    private static String str(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    private static Long lng(Object o) {
        if (o == null) {
            return null;
        }
        if (o instanceof Number n) {
            return n.longValue();
        }
        return Long.parseLong(String.valueOf(o));
    }

    @PostMapping("/holds")
    public LegalHold addHold(@RequestBody Map<String, String> body) {
        return service.addLegalHold(body.get("holdId"), body.get("subjectPattern"), body.get("reason"));
    }

    @DeleteMapping("/holds/{holdId}")
    public Map<String, Object> removeHold(@PathVariable String holdId) {
        boolean removed = service.removeLegalHold(holdId);
        return Map.of("holdId", holdId, "removed", removed);
    }

    /** 只读状态：账本是否健康/关闭、最早受影响序号、记录总数、outbox 重投继续位置、兼容边界、清除统计。 */
    @GetMapping("/state")
    public Map<String, Object> state() {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("ledgerClosed", service.ledger().isClosed());
        view.put("healthy", !service.ledger().isClosed());
        view.put("firstTamperedSequence", service.ledger().firstTamperedSequence());
        view.put("eventCount", service.ledger().count());
        view.put("nextSequence", service.ledger().nextSequence());
        view.put("resumeOutboxId", service.outbox().resumePosition());
        view.put("legacyMode", service.ledger().legacyMode());
        view.put("legacyBoundaryDataSeq", service.ledger().legacyBoundaryDataSeq());
        long compliancePurged = service.ledger().purgeMarks().stream()
                .filter(m -> "COMPLIANCE".equals(m.source())).count();
        long retentionPurged = service.ledger().purgeMarks().size() - compliancePurged;
        view.put("purgedTotal", service.ledger().purgeMarks().size());
        view.put("purgedByCompliance", compliancePurged);
        view.put("purgedByRetention", retentionPurged);
        if (service.ledger().legacyMode()) {
            view.put("compatibilityNote",
                    "老数据目录已升级：序号1.." + service.ledger().legacyBoundaryDataSeq()
                            + " 的历史链可验证；升级前的末尾整段删除不在新核验能力覆盖范围内，升级后写入的记录具备完整保护");
        }
        return view;
    }
}
