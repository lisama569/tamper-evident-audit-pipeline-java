package com.github.lisama569.tamperevidentauditpipelinejava.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.CompliancePurgeRequest;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.CompliancePurgeResult;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.CompatibilityReport;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.VerifyResult;
import com.github.lisama569.tamperevidentauditpipelinejava.model.IngestResult;
import com.github.lisama569.tamperevidentauditpipelinejava.model.RejectReason;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.LegalHold;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.PurgeResult;
import com.github.lisama569.tamperevidentauditpipelinejava.service.AuditPipelineService;
import java.util.LinkedHashMap;
import java.util.List;
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

    /** 合规清除预演：不写帧、不删 DEK，返回命中/被挡清单与每条依据。 */
    @PostMapping("/compliance/purge/preview")
    public CompliancePurgeResult previewCompliance(@RequestBody JsonNode body) {
        return service.previewCompliancePurge(toPurgeRequest(body, true));
    }

    /** 合规清除执行：同一 requestId 幂等（含重启），第二次返回与首次完全一致的结论。 */
    @PostMapping("/compliance/purge/execute")
    public CompliancePurgeResult executeCompliance(@RequestBody JsonNode body) {
        return service.executeCompliancePurge(toPurgeRequest(body, false));
    }

    /** 全量完整性核验（只读，不依赖运行期内存，结论重启一致）。 */
    @PostMapping("/verify")
    public VerifyResult verify() {
        return service.verifyLedger();
    }

    /** 分段核验：只重算指定序号区间，结论对应明确记录范围。 */
    @PostMapping("/verify/range")
    public VerifyResult verifyRange(@RequestParam("from") long from, @RequestParam("to") long to) {
        return service.verifyLedgerRange(from, to);
    }

    /** 老数据目录兼容/升级结论（全新目录返回 legacy=false）。 */
    @GetMapping("/compatibility")
    public CompatibilityReport compatibility() {
        CompatibilityReport report = service.ledger().compatibilityReport();
        return report != null ? report
                : new CompatibilityReport(false, "2", List.of(), List.of());
    }

    private static CompliancePurgeRequest toPurgeRequest(JsonNode b, boolean forcedDryRun) {
        Long from = b.hasNonNull("fromSequence") ? b.get("fromSequence").asLong() : null;
        Long to = b.hasNonNull("toSequence") ? b.get("toSequence").asLong() : null;
        String subject = b.hasNonNull("subject") ? b.get("subject").asText() : null;
        boolean dryRun = forcedDryRun || b.path("dryRun").asBoolean(false);
        return new CompliancePurgeRequest(b.path("requestId").asText(null),
                b.path("reason").asText(null), subject, from, to, dryRun);
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

    /** 只读状态：账本是否健康/关闭、破坏证据与最早受影响序号、记录总数、outbox 重投继续位置。 */
    @GetMapping("/state")
    public Map<String, Object> state() {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("ledgerClosed", service.ledger().isClosed());
        view.put("firstTamperedSequence", service.ledger().firstTamperedSequence());
        view.put("tamperEvidence", service.ledger().evidence().name());
        view.put("tamperDetail", service.ledger().tamperDetail());
        view.put("eventCount", service.ledger().all().size());
        view.put("nextSequence", service.ledger().nextSequence());
        view.put("frameCount", service.ledger().frameCount());
        view.put("resumeOutboxId", service.outbox().resumePosition());
        return view;
    }
}
