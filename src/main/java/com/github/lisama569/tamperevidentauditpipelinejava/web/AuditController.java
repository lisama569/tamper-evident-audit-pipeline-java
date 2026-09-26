package com.github.lisama569.tamperevidentauditpipelinejava.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.PurgeReport;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.RejectReason;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;
import com.github.lisama569.tamperevidentauditpipelinejava.ingest.IngestResult;
import com.github.lisama569.tamperevidentauditpipelinejava.ingest.IngestService;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.LegalHoldStore;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.RetentionService;
import com.github.lisama569.tamperevidentauditpipelinejava.storage.CompactionJournal;
import com.github.lisama569.tamperevidentauditpipelinejava.storage.TamperEvidentStore;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.DeliveryService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 审计流水线 REST 接口。
 *
 * <ul>
 *   <li>POST /api/audit/events：单对象或数组批量接入；支持头 X-Idempotency-Key；</li>
 *   <li>GET  /api/audit/records、/api/audit/records/{seq}：查询留存记录；</li>
 *   <li>POST /api/audit/holds / DELETE：法律保留登记/解除；</li>
 *   <li>POST /api/audit/purge/expired：保留到期清除；</li>
 *   <li>POST /api/audit/erase：合规清除请求；</li>
 *   <li>GET  /api/audit/compactions：清除凭证；</li>
 *   <li>GET  /api/audit/delivery：转发状态；POST /api/audit/delivery/{seq}/replay：死信重放；</li>
 *   <li>GET  /api/audit/health：密封状态/末序号。</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private static final Logger log = LoggerFactory.getLogger(AuditController.class);

    private final IngestService ingest;
    private final TamperEvidentStore store;
    private final RetentionService retention;
    private final LegalHoldStore holds;
    private final CompactionJournal journal;
    private final DeliveryService delivery;
    private final ObjectMapper mapper;

    public AuditController(IngestService ingest, TamperEvidentStore store,
                           RetentionService retention, LegalHoldStore holds,
                           CompactionJournal journal, DeliveryService delivery,
                           ObjectMapper mapper) {
        this.ingest = ingest;
        this.store = store;
        this.retention = retention;
        this.holds = holds;
        this.journal = journal;
        this.delivery = delivery;
        this.mapper = mapper;
    }

    @PostMapping("/events")
    public ResponseEntity<?> ingest(@RequestBody(required = false) String rawBody,
                                    @RequestHeader(value = "X-Idempotency-Key", required = false)
                                    String headerKey) {
        JsonNode root;
        try {
            root = rawBody == null ? null : mapper.readTree(rawBody);
        } catch (JsonProcessingException e) {
            return badRequest("MALFORMED_JSON", "请求体不是合法 JSON: " + e.getOriginalMessage());
        }
        if (root == null || root.isNull()) {
            return badRequest("MALFORMED_JSON", "请求体为空");
        }
        List<JsonNode> items = new ArrayList<>();
        if (root.isArray()) {
            root.forEach(items::add);
        } else if (root.isObject()) {
            items.add(root);
        } else {
            return badRequest(RejectReason.PAYLOAD_NOT_OBJECT.name(),
                    "顶层必须是事件对象或事件数组");
        }

        List<ApiDtos.ItemResult> results = new ArrayList<>();
        int accepted = 0, duplicate = 0, rejected = 0, sealed = 0;
        for (JsonNode item : items) {
            IngestResult r;
            if (item == null || !item.isObject()) {
                r = IngestResult.rejected(RejectReason.PAYLOAD_NOT_OBJECT, null, "数组元素必须是事件对象");
            } else {
                r = ingest.submit(item, headerKey);
            }
            ApiDtos.ItemResult dto = toItem(r);
            results.add(dto);
            switch (r.outcome()) {
                case ACCEPTED -> accepted++;
                case DUPLICATE -> duplicate++;
                case REJECTED -> rejected++;
                case STORAGE_SEALED -> sealed++;
            }
        }
        return ResponseEntity.ok(new ApiDtos.BatchResponse(results, accepted, duplicate, rejected, sealed));
    }

    @GetMapping("/records")
    public List<StoredRecord> records() {
        return store.all();
    }

    @GetMapping("/records/{seq}")
    public ResponseEntity<?> record(@PathVariable long seq) {
        return store.get(seq)
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ApiDtos.MessageResponse("记录不存在或已被清除: seq=" + seq)));
    }

    @PostMapping("/records/{seq}/holds")
    public ApiDtos.MessageResponse placeHold(@PathVariable long seq,
                                             @RequestBody ApiDtos.HoldRequest req) {
        if (req.holdId() == null || req.holdId().isBlank()) {
            throw new IllegalArgumentException("holdId 必填");
        }
        if (store.get(seq).isEmpty()) {
            throw new IllegalArgumentException("记录不存在或已被清除: seq=" + seq);
        }
        holds.place(seq, req.holdId(),
                req.reason() == null ? "" : req.reason(),
                req.by() == null ? "anonymous" : req.by());
        return new ApiDtos.MessageResponse("已对 seq=" + seq + " 设置法律保留 " + req.holdId());
    }

    @DeleteMapping("/records/{seq}/holds")
    public ResponseEntity<?> releaseHold(@PathVariable long seq,
                                         @RequestParam(required = false) String holdId) {
        boolean ok = holds.release(seq, holdId);
        return ok
                ? ResponseEntity.ok(new ApiDtos.MessageResponse("已解除 seq=" + seq + " 的法律保留"))
                : ResponseEntity.badRequest()
                .body(new ApiDtos.MessageResponse("seq=" + seq + " 无匹配的法律保留"));
    }

    @PostMapping("/purge/expired")
    public PurgeReport purgeExpired(@RequestBody(required = false) ApiDtos.PurgeRequest req) {
        String mode = req == null || req.mode() == null || req.mode().isBlank()
                ? RetentionService.MODE_LOGICAL : req.mode();
        return retention.purgeExpired(mode, Instant.now());
    }

    @PostMapping("/erase")
    public PurgeReport erase(@RequestBody ApiDtos.EraseRequest req) {
        if (req.seqs() == null || req.seqs().isEmpty()) {
            throw new IllegalArgumentException("seqs 必填且非空");
        }
        String mode = req.mode() == null || req.mode().isBlank()
                ? RetentionService.MODE_ERASURE : req.mode();
        String by = req.requestedBy() == null ? "anonymous" : req.requestedBy();
        return retention.complianceErase(new java.util.TreeSet<>(req.seqs()), by, mode);
    }

    @GetMapping("/compactions")
    public Object compactions() {
        return Map.of("entries", journal.entries());
    }

    @GetMapping("/delivery")
    public Object delivery() {
        return Map.of("records", delivery.deliverySnapshot());
    }

    @PostMapping("/delivery/{seq}/replay")
    public ResponseEntity<?> replay(@PathVariable long seq) {
        boolean ok = delivery.replay(seq);
        return ok
                ? ResponseEntity.ok(new ApiDtos.MessageResponse("已将 seq=" + seq + " 从死信重置为待投递"))
                : ResponseEntity.badRequest()
                .body(new ApiDtos.MessageResponse("seq=" + seq + " 不在死信状态，无法重放"));
    }

    @GetMapping("/health")
    public Object health() {
        return Map.of(
                "sealed", store.isSealed(),
                "firstAffectedSeq", store.firstAffectedSeq(),
                "sealedReason", store.sealedReason() == null ? "" : store.sealedReason(),
                "lastSeq", store.lastSeq(),
                "erasedSeqs", store.erasedSeqs(),
                "legalHolds", holds.snapshot());
    }

    private ApiDtos.ItemResult toItem(IngestResult r) {
        StoredRecord rec = r.record();
        return new ApiDtos.ItemResult(r.outcome(), r.reason(), r.field(), r.message(),
                rec == null ? null : rec.seq(),
                rec == null ? null : rec.recordId(),
                rec == null ? null : rec.hash());
    }

    private ResponseEntity<?> badRequest(String code, String message) {
        return ResponseEntity.badRequest().body(Map.of("code", code, "message", message));
    }
}
