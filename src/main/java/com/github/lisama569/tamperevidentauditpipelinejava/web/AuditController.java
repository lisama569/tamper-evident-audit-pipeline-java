package com.github.lisama569.tamperevidentauditpipelinejava.web;

import com.fasterxml.jackson.databind.JsonNode;
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

    @PostMapping("/holds")
    public LegalHold addHold(@RequestBody Map<String, String> body) {
        return service.addLegalHold(body.get("holdId"), body.get("subjectPattern"), body.get("reason"));
    }

    @DeleteMapping("/holds/{holdId}")
    public Map<String, Object> removeHold(@PathVariable String holdId) {
        boolean removed = service.removeLegalHold(holdId);
        return Map.of("holdId", holdId, "removed", removed);
    }

    /** 只读状态：账本是否健康/关闭、最早受影响序号、记录总数、outbox 重投继续位置。 */
    @GetMapping("/state")
    public Map<String, Object> state() {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("ledgerClosed", service.ledger().isClosed());
        view.put("firstTamperedSequence", service.ledger().firstTamperedSequence());
        view.put("eventCount", service.ledger().all().size());
        view.put("nextSequence", service.ledger().nextSequence());
        view.put("resumeOutboxId", service.outbox().resumePosition());
        return view;
    }
}
