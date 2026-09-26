package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.lisama569.tamperevidentauditpipelinejava.config.PipelineProperties;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.AuditEvent;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.DeliveryRecord;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.DeliveryState;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.ErrorClass;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.HmacSigner;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.DeliveryService;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.ErrorClassifier;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.OutboxStore;
import com.github.lisama569.tamperevidentauditpipelinejava.storage.FileAppendStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 转发：错误分类、重试成功、不可重试入死信、死信重放、重启从可预期位置续投、
 * 成功后不重复转发、失败不丢失。
 */
class DeliveryServiceTest {

    private static final Logger log = LoggerFactory.getLogger(DeliveryServiceTest.class);

    private ObjectMapper mapper() {
        ObjectMapper m = new ObjectMapper();
        m.registerModule(new JavaTimeModule());
        m.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return m;
    }

    private PipelineProperties props() {
        PipelineProperties p = new PipelineProperties();
        p.setRetryInitialBackoffMs(10);
        p.setRetryMaxBackoffMs(50);
        p.setRetryMaxAttempts(5);
        p.setRetryOnStartup(false); // 测试中手动 tick，避免后台线程干扰
        return p;
    }

    private AuditEvent ev(String key) {
        return new AuditEvent(key, "s", "T", Instant.now(), "a", "b", 90, Map.of());
    }

    record Ctx(FileAppendStore store, OutboxStore outbox, DeliveryService delivery,
               ScriptedForwarder forwarder) {
    }

    /** 驱动一次投递扫描；若处于退避窗口则等待后重试，最多等待 timeoutMs。 */
    private void pump(DeliveryService d, long timeoutMs) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        d.tick();
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(15);
            d.tick();
        }
    }

    private Ctx ctx(Path dir, PipelineProperties props, ScriptedForwarder fwd) throws Exception {
        ObjectMapper mapper = mapper();
        FileAppendStore store = new FileAppendStore(dir, new HmacSigner("s"), mapper);
        store.initialize();
        OutboxStore outbox = new OutboxStore(dir, mapper);
        outbox.initialize();
        DeliveryService delivery = new DeliveryService(outbox, store, fwd, props);
        return new Ctx(store, outbox, delivery, fwd);
    }

    @Test
    void errorClassification() {
        assertEquals(ErrorClass.RETRYABLE, ErrorClassifier.classifyThrowable(new ConnectException()));
        assertEquals(ErrorClass.RETRYABLE, ErrorClassifier.classifyThrowable(new SocketTimeoutException()));
        assertEquals(ErrorClass.RETRYABLE, ErrorClassifier.classifyStatus(503));
        assertEquals(ErrorClass.RETRYABLE, ErrorClassifier.classifyStatus(429));
        assertEquals(ErrorClass.NON_RETRYABLE, ErrorClassifier.classifyStatus(400));
        assertEquals(ErrorClass.NON_RETRYABLE, ErrorClassifier.classifyStatus(422));
        assertNull(ErrorClassifier.classifyStatus(200));
        assertNull(ErrorClassifier.classifyStatus(204));
        log.info("【错误分类】ConnectException/超时=RETRYABLE, 5xx/429=RETRYABLE, 其他4xx=NON_RETRYABLE, 2xx=成功");
    }

    @Test
    void retryableFailureThenSuccess_deliveredExactlyOnceNoLoss(@TempDir Path base) throws Exception {
        ScriptedForwarder fwd = new ScriptedForwarder();
        Ctx c = ctx(base.resolve("a"), props(), fwd);
        StoredRecord r1 = c.store().append(ev("k1"));
        c.outbox().register(r1);
        fwd.failThenOk(1, 2, ErrorClass.RETRYABLE);

        // 退避重试：前两次失败、第三次成功（pump 会跨越退避窗口）
        pump(c.delivery(), 1000);
        DeliveryRecord finalState = c.outbox().get(1).orElseThrow();
        assertEquals(DeliveryState.DELIVERED, finalState.state());
        assertEquals(2, finalState.attempts(), "成功前经历了2次失败，attempts记录失败次数");
        // 对端仅在成功时记录一次送达
        assertEquals(java.util.List.of(r1.recordId()), fwd.deliveredRecordIds());
        // DELIVERED 后再次 tick 不得重复转发
        c.delivery().tick();
        assertEquals(2, c.outbox().get(1).orElseThrow().attempts());
        log.info("【重试成功】输入=seq1前2次可重试失败 判定依据=RETRYABLE指数退避重试 最终状态=DELIVERED attempts=3, 对端成功送达次数=1");
    }

    @Test
    void nonRetryableGoesDeadLetterImmediately_andCanReplay(@TempDir Path base) throws Exception {
        ScriptedForwarder fwd = new ScriptedForwarder();
        Ctx c = ctx(base.resolve("b"), props(), fwd);
        StoredRecord r1 = c.store().append(ev("k1"));
        c.outbox().register(r1);
        fwd.alwaysFail(1, ErrorClass.NON_RETRYABLE);

        c.delivery().tick();
        DeliveryRecord dr = c.outbox().get(1).orElseThrow();
        assertEquals(DeliveryState.DEAD_LETTER, dr.state());
        assertEquals(1, dr.attempts(), "不可重试错误不应反复尝试");
        log.info("【死信】输入=seq1返回422类不可重试 判定依据=NON_RETRYABLE 最终状态=DEAD_LETTER afterAttempts={}",
                dr.attempts());

        // 重放：把脚本改为成功后重放
        fwd.failThenOk(1, 0, ErrorClass.RETRYABLE);
        assertTrue(c.delivery().replay(1));
        pump(c.delivery(), 500);
        assertEquals(DeliveryState.DELIVERED, c.outbox().get(1).orElseThrow().state());
        log.info("【死信重放】人工重放后 seq1 最终状态=DELIVERED");
    }

    @Test
    void retryExhaustionEntersDeadLetter(@TempDir Path base) throws Exception {
        ScriptedForwarder fwd = new ScriptedForwarder();
        Ctx c = ctx(base.resolve("c"), props(), fwd);
        StoredRecord r1 = c.store().append(ev("k1"));
        c.outbox().register(r1);
        fwd.alwaysFail(1, ErrorClass.RETRYABLE); // 一直可重试失败

        pump(c.delivery(), 1500);
        assertEquals(DeliveryState.DEAD_LETTER, c.outbox().get(1).orElseThrow().state());
        assertEquals(5, c.outbox().get(1).orElseThrow().attempts());
        log.info("【重试耗尽】连续5次可重试失败后进入 DEAD_LETTER，记录仍保留不丢失，等待重放");
    }

    @Test
    void restartResumesFromExpectedPosition_inOrderNoDuplicates(@TempDir Path base) throws Exception {
        Path dir = base.resolve("restart");
        PipelineProperties props = props();

        // 第一个“进程”：追加 3 条，seq1 成功，seq2 可重试失败（PENDING），seq3 尚未轮到
        ScriptedForwarder f1 = new ScriptedForwarder();
        Ctx c1 = ctx(dir, props, f1);
        StoredRecord r1 = c1.store().append(ev("k1"));
        StoredRecord r2 = c1.store().append(ev("k2"));
        StoredRecord r3 = c1.store().append(ev("k3"));
        c1.outbox().register(r1);
        c1.outbox().register(r2);
        c1.outbox().register(r3);
        f1.failThenOk(1, 0, ErrorClass.RETRYABLE);
        f1.alwaysFail(2, ErrorClass.RETRYABLE);
        c1.delivery().tick(); // seq1 DELIVERED
        c1.delivery().tick(); // seq2 fail -> PENDING(backoff)
        assertEquals(DeliveryState.DELIVERED, c1.outbox().get(1).orElseThrow().state());
        assertNotEquals(DeliveryState.DELIVERED, c1.outbox().get(2).orElseThrow().state());
        assertEquals(DeliveryState.PENDING, c1.outbox().get(3).orElseThrow().state());
        log.info("【重启前】seq1=DELIVERED seq2={} seq3=PENDING（游标停在 seq2）",
                c1.outbox().get(2).orElseThrow().state());

        // “重启”：重新从磁盘加载 outbox 与 store，换一个这次会成功的转发器
        ScriptedForwarder f2 = new ScriptedForwarder();
        ObjectMapper mapper = mapper();
        FileAppendStore store2 = new FileAppendStore(dir, new HmacSigner("s"), mapper);
        store2.initialize();
        OutboxStore outbox2 = new OutboxStore(dir, mapper);
        outbox2.initialize();
        DeliveryService d2 = new DeliveryService(outbox2, store2, f2, props);

        // 状态必须从磁盘恢复
        assertEquals(DeliveryState.DELIVERED, outbox2.get(1).orElseThrow().state());
        assertNotEquals(DeliveryState.DELIVERED, outbox2.get(2).orElseThrow().state());

        pump(d2, 1500); // 跨越退避窗口，按游标顺序投递 seq2、seq3
        assertEquals(DeliveryState.DELIVERED, outbox2.get(2).orElseThrow().state());
        assertEquals(DeliveryState.DELIVERED, outbox2.get(3).orElseThrow().state());

        // 顺序与不重复：seq1 由进程1送达一次，seq2/seq3 由进程2各送达一次
        assertEquals(1, f1.deliveryCountOf(r1.recordId()));
        assertEquals(0, f2.deliveryCountOf(r1.recordId()), "已 DELIVERED 的 seq1 重启后不得重复转发");
        assertEquals(1, f2.deliveryCountOf(r2.recordId()));
        assertEquals(1, f2.deliveryCountOf(r3.recordId()));
        assertEquals(java.util.List.of(r2.recordId(), r3.recordId()), f2.deliveredRecordIds());
        log.info("【重启续投】重启后从游标位置 seq2 继续，seq1 不重复，顺序送达 [seq2,seq3]，无丢失");
    }
}
