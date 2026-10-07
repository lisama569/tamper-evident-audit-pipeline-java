package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.CompliancePurgeRequest;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.CompliancePurgeResult;
import com.github.lisama569.tamperevidentauditpipelinejava.compliance.RecordDecision;
import com.github.lisama569.tamperevidentauditpipelinejava.config.PipelineProperties;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.AppendOnlyLedger;
import com.github.lisama569.tamperevidentauditpipelinejava.ledger.TamperException;
import com.github.lisama569.tamperevidentauditpipelinejava.model.IngestResult;
import com.github.lisama569.tamperevidentauditpipelinejava.model.RejectReason;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.PurgeSource;
import com.github.lisama569.tamperevidentauditpipelinejava.service.AuditPipelineService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 端到端（经服务门面，含“重启新实例”）：合规清除预演/执行/幂等/重启一致；
 * 执行中途崩溃（模拟部分 PURGE 帧落盘）后重放结论与一次成功一致；
 * 破坏后事件接入与合规/到期清除均被明确拒绝；state 能看到破坏状态与最早受影响位置。
 */
class CompliancePipelineEndToEndTest {

    private static final Logger LOG = Logger.getLogger(CompliancePipelineEndToEndTest.class.getName());
    private final ObjectMapper mapper = new ObjectMapper();
    private @TempDir Path dir;

    private PipelineProperties props() {
        PipelineProperties p = new PipelineProperties();
        p.setStorageDir(dir);
        p.setAutoForward(false);
        return p;
    }

    private long ingest(AuditPipelineService svc, String eventId, String subject) throws Exception {
        String body = "{\"source\":\"web\",\"eventId\":\"" + eventId + "\",\"eventType\":\"login\","
                + "\"occurredAt\":" + System.currentTimeMillis() + ",\"subject\":\"" + subject + "\"}";
        IngestResult r = svc.ingest(mapper.readTree(body));
        assertTrue(r.accepted(), () -> "ingest 应成功: " + r.reason());
        return r.sequence();
    }

    @Test
    void complianceLifecyclePreviewExecuteReplayAcrossRestart(TestInfo info) throws Exception {
        AuditPipelineService s1 = new AuditPipelineService(props(), mapper);
        ingest(s1, "e1", "alice");
        ingest(s1, "e2", "alice");
        ingest(s1, "e3", "bob");
        s1.addLegalHold("h1", "bob", "freeze");

        CompliancePurgeRequest req = new CompliancePurgeRequest("case-1", "GDPR",
                "alice", null, null, false);
        CompliancePurgeResult preview = s1.previewCompliancePurge(req);
        assertEquals(List.of(1L, 2L), preview.purgedSequences());

        CompliancePurgeResult exec = s1.executeCompliancePurge(req);
        assertEquals(List.of(1L, 2L), exec.purgedSequences());
        assertEquals(PurgeSource.COMPLIANCE, s1.ledger().at(1).orElseThrow().purgeSource());

        // 同进程幂等
        CompliancePurgeResult replay = s1.executeCompliancePurge(req);
        assertEquals(exec.purgedSequences(), replay.purgedSequences());
        assertEquals(exec.items().size(), replay.items().size());
        s1.close();

        // 重启（全新服务实例，结论只来自磁盘日志）
        AuditPipelineService s2 = new AuditPipelineService(props(), mapper);
        CompliancePurgeResult afterRestart = s2.executeCompliancePurge(req);
        assertEquals(exec.purgedSequences(), afterRestart.purgedSequences());
        assertEquals(exec.items().size(), afterRestart.items().size());
        // 历史存在性仍可审计：envelope 在、链可验、明文不可恢复
        assertTrue(s2.verifyLedger().healthy());
        assertNotNull(s2.ledger().at(1).orElseThrow().hash());
        assertNull(s2.ledger().at(1).orElseThrow().payloadJson());
        assertEquals("case-1", s2.ledger().at(1).orElseThrow().purgeRequestId());
        s2.close();
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=2条alice+1条bob(hold)"
                + " 判定依据=预演={1,2}->执行={1,2}->同进程/重启重放一致"
                + " 最终状态=明文不可恢复但envelope/链/requestId可审计，bob未动");
    }

    @Test
    void crashMidwayPurgeCompletesWithSameOutcomeOnReplay(TestInfo info) throws Exception {
        AuditPipelineService s1 = new AuditPipelineService(props(), mapper);
        for (int i = 1; i <= 4; i++) {
            ingest(s1, "e" + i, "zoe");
        }
        // 先发起范围请求（仅落 REQUEST 日志），再手工只让 seq1、seq2 完成 PURGE，模拟执行中途崩溃
        var req = new CompliancePurgeRequest("crash-1", "legal", null, 1L, 4L, false);
        s1.ledger().markPurged(1L, PurgeSource.COMPLIANCE, "crash-1", "legal");
        s1.ledger().markPurged(2L, PurgeSource.COMPLIANCE, "crash-1", "legal");
        // 关键：写入 REQUEST 行（与崩溃时已完成的边界一致）
        Files.writeString(dir.resolve("purge-requests.log"),
                "{\"op\":\"REQUEST\",\"requestId\":\"crash-1\",\"reason\":\"legal\","
                        + "\"fromSequence\":1,\"toSequence\":4,\"dryRun\":false,"
                        + "\"evalUpToSequence\":4,\"ts\":" + System.currentTimeMillis() + "}\n");
        s1.close();

        // 重启后重放同一请求：seq1,2 计入已完成，seq3,4 补清，最终集合 {1,2,3,4}
        AuditPipelineService s2 = new AuditPipelineService(props(), mapper);
        CompliancePurgeResult r = s2.executeCompliancePurge(req);
        assertEquals(List.of(1L, 2L, 3L, 4L), r.purgedSequences());
        assertTrue(r.blockedByLegalHold().isEmpty());
        for (long seq = 1; seq <= 4; seq++) {
            assertNull(s2.ledger().at(seq).orElseThrow().payloadJson());
            assertEquals(PurgeSource.COMPLIANCE, s2.ledger().at(seq).orElseThrow().purgeSource());
        }
        // 再来一次幂等：结论一致，不产生新动作
        CompliancePurgeResult again = s2.executeCompliancePurge(req);
        assertEquals(r.purgedSequences(), again.purgedSequences());
        assertTrue(s2.verifyLedger().healthy());
        s2.close();
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=REQUEST已落+seq1,2已PURGE后崩溃"
                + " 判定依据=重放识别本requestId已完成部分并补清3,4 最终状态=集合{1,2,3,4}与一次成功一致");
    }

    @Test
    void writesAndPurgesRejectedAndStateVisibleAfterTamper(TestInfo info) throws Exception {
        AuditPipelineService s1 = new AuditPipelineService(props(), mapper);
        ingest(s1, "e1", "alice");
        ingest(s1, "e2", "bob");
        s1.close();

        // 停服、改文件
        Path ledger = dir.resolve("ledger.log");
        var lines = Files.readAllLines(ledger);
        String fr = lines.get(0);
        int i = fr.indexOf("\"body\":\"") + 8;
        char c = fr.charAt(i);
        lines.set(0, fr.substring(0, i) + (c == 'A' ? 'B' : 'A') + fr.substring(i + 1));
        Files.write(ledger, lines);

        // 再启动：降级只读
        AuditPipelineService s2 = new AuditPipelineService(props(), mapper);
        assertTrue(s2.ledger().isClosed());
        assertEquals(1L, s2.ledger().firstTamperedSequence());

        // 新事件接入被明确拒绝（LEDGER_TAMPERED）
        IngestResult ing = s2.ingest(mapper.readTree(
                "{\"source\":\"web\",\"eventId\":\"x\",\"eventType\":\"t\",\"occurredAt\":"
                        + System.currentTimeMillis() + "}"));
        assertFalse(ing.accepted());
        assertEquals(RejectReason.LEDGER_TAMPERED, ing.reason());

        // 合规清除与到期清除都被拒绝
        var req = new CompliancePurgeRequest("r", "reason", null, 1L, 2L, false);
        assertThrows(TamperException.class, () -> s2.executeCompliancePurge(req));
        assertThrows(TamperException.class, s2::enforceRetention);

        // 状态查询可见破坏状态与位置
        var st = stateOf(s2);
        assertEquals(true, st.get("ledgerClosed"));
        assertEquals(1L, st.get("firstTamperedSequence"));
        assertNotEquals("OK", st.get("tamperEvidence"));
        assertNotNull(st.get("tamperDetail"));
        s2.close();
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=停服改seq1再启动"
                + " 判定依据=降级打开 state=" + st
                + " 最终状态=追加/合规清除/到期清除全部拒绝，state可见破坏证据与位置");
    }

    @SuppressWarnings("unchecked")
    private java.util.Map<String, Object> stateOf(AuditPipelineService svc) {
        // 直接走与控制器一致的只读视图组装逻辑
        java.util.Map<String, Object> v = new java.util.LinkedHashMap<>();
        v.put("ledgerClosed", svc.ledger().isClosed());
        v.put("firstTamperedSequence", svc.ledger().firstTamperedSequence());
        v.put("tamperEvidence", svc.ledger().evidence().name());
        v.put("tamperDetail", svc.ledger().tamperDetail());
        v.put("eventCount", svc.ledger().all().size());
        v.put("nextSequence", svc.ledger().nextSequence());
        return v;
    }
}
