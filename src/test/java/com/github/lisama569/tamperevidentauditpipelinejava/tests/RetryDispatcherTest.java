package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.github.lisama569.tamperevidentauditpipelinejava.forward.ForwardOutcome;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.Forwarder;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.Forwarder.ForwardResult;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.OutboxEntry;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.OutboxStore;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.RetryDispatcher;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 失败重投语义测试：错误类别区分、不重复转发、指数退避、死信、重启后从最小未完成位置继续。
 */
class RetryDispatcherTest {

    private static final Logger LOG = Logger.getLogger(RetryDispatcherTest.class.getName());

    private @TempDir Path dir;

    /** 可编程假转发器：按调用次数返回预设结果，并记录每次收到的 outboxId。 */
    static final class ScriptedForwarder implements Forwarder {
        final List<ForwardResult> script;
        final List<Long> seenIds = new ArrayList<>();
        int calls;

        ScriptedForwarder(ForwardResult... results) {
            this.script = List.of(results);
        }

        @Override
        public synchronized ForwardResult forward(OutboxEntry entry) {
            seenIds.add(entry.id());
            ForwardResult r = script.get(Math.min(calls, script.size() - 1));
            calls++;
            return r;
        }
    }

    private RetryDispatcher dispatcher(OutboxStore store, Forwarder f, int maxAttempts,
                                       long initialDelay, long recoverMs) {
        return new RetryDispatcher(store, f, maxAttempts, initialDelay, 10_000L, 60_000L, recoverMs);
    }

    @Test
    void successMarksSentAndNoDuplicateForward(TestInfo info) {
        OutboxStore store = new OutboxStore(dir.resolve("outbox.log"));
        store.register(1, "k1", "p1");
        ScriptedForwarder f = new ScriptedForwarder(ForwardResult.success());
        RetryDispatcher d = dispatcher(store, f, 3, 10, 60_000);

        int processed = d.dispatchOnce();
        // 再来多轮：SENT 是终态，绝不重复转发
        d.dispatchOnce();
        d.dispatchOnce();

        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=1条PENDING+成功脚本"
                + " 判定依据=转发调用次数=" + f.calls + " 所见id=" + f.seenIds
                + " 最终状态=" + store.find(1L).orElseThrow().status());
        assertEquals(1, processed);
        assertEquals(1, f.calls);
        assertEquals(OutboxEntry.SENT, store.find(1L).orElseThrow().status());
    }

    @Test
    void retryableFailuresBackoffThenSucceed(TestInfo info) {
        OutboxStore store = new OutboxStore(dir.resolve("outbox.log"));
        store.register(1, "k1", "p1");
        ScriptedForwarder f = new ScriptedForwarder(
                ForwardResult.retryable("HTTP_503", "busy"),
                ForwardResult.retryable("NETWORK", "reset"),
                ForwardResult.success());
        RetryDispatcher d = dispatcher(store, f, 5, 2000, 60_000);

        d.dispatchOnce(); // 失败→PENDING，下次时间在未来
        assertEquals(OutboxEntry.PENDING, store.find(1L).orElseThrow().status());
        assertEquals("HTTP_503", store.find(1L).orElseThrow().lastErrorCategory());
        assertEquals(1, store.find(1L).orElseThrow().attempts());

        // 退避未到：没有到期条目
        assertEquals(0, d.dispatchOnce());
        // 把下次尝试时间拨到过去，模拟退避结束
        store.markRetry(1L, System.currentTimeMillis() - 1, "NETWORK");
        assertEquals(1, d.dispatchOnce()); // 第二次失败
        store.markRetry(1L, System.currentTimeMillis() - 1, "NETWORK");
        assertEquals(1, d.dispatchOnce()); // 第三次成功

        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定=503/网络两次可重试后退避到期成功"
                + " 总调用=" + f.calls + " 最终状态=" + store.find(1L).orElseThrow().status());
        assertEquals(3, f.calls);
        assertEquals(OutboxEntry.SENT, store.find(1L).orElseThrow().status());
    }

    @Test
    void nonRetryableGoesStraightToDead(TestInfo info) {
        OutboxStore store = new OutboxStore(dir.resolve("outbox.log"));
        store.register(1, "k1", "p1");
        ScriptedForwarder f = new ScriptedForwarder(ForwardResult.nonRetryable("HTTP_400", "bad payload"));
        RetryDispatcher d = dispatcher(store, f, 5, 2000, 60_000);
        d.dispatchOnce();
        d.dispatchOnce(); // DEAD 终态，不再调用
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定=400不可重试"
                + " 调用次数=" + f.calls + " 最终状态=" + store.find(1L).orElseThrow().status());
        assertEquals(OutboxEntry.DEAD, store.find(1L).orElseThrow().status());
        assertEquals("HTTP_400", store.find(1L).orElseThrow().lastErrorCategory());
        assertEquals(1, f.calls);
    }

    @Test
    void retriesExhaustedGoesToDead(TestInfo info) {
        OutboxStore store = new OutboxStore(dir.resolve("outbox.log"));
        store.register(1, "k1", "p1");
        ScriptedForwarder f = new ScriptedForwarder(ForwardResult.retryable("HTTP_500", "err"));
        // 退避初始与上限都为 0：每次失败后立即可再次认领
        RetryDispatcher d = new RetryDispatcher(store, f, 3, 0L, 0L, 60_000L, 60_000L);
        for (int round = 0; round < 5; round++) {
            d.dispatchOnce();
        }
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定=连续500超过最大尝试3次"
                + " attempts=" + store.find(1L).orElseThrow().attempts()
                + " 最终状态=" + store.find(1L).orElseThrow().status());
        assertEquals(OutboxEntry.DEAD, store.find(1L).orElseThrow().status());
        assertEquals(3, store.find(1L).orElseThrow().attempts());
    }

    @Test
    void backoffIsExponential(TestInfo info) {
        OutboxStore store = new OutboxStore(dir.resolve("outbox.log"));
        RetryDispatcher d = dispatcher(store,
                new ScriptedForwarder(ForwardResult.success()), 5, 100, 60_000);
        assertEquals(100, d.backoffMs(1));
        assertEquals(200, d.backoffMs(2));
        assertEquals(400, d.backoffMs(3));
        assertEquals(10_000, d.backoffMs(100));
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定依据=100/200/400/上限10000 最终状态=指数退避确定");
    }

    @Test
    void dispatchRespectsOrderAndResumeFromSmallestPosition(TestInfo info) {
        // 三条记录：1 SENT，2 PENDING，3 PENDING → 恢复位置=2，且按 id 升序处理
        OutboxStore store = new OutboxStore(dir.resolve("outbox.log"));
        store.register(1, "k1", "p1");
        store.register(2, "k2", "p2");
        store.register(3, "k3", "p3");
        store.markSent(1L);
        assertEquals(2L, store.resumePosition());

        List<Long> order = new ArrayList<>();
        Forwarder f = e -> {
            order.add(e.id());
            return ForwardResult.success();
        };
        RetryDispatcher d = dispatcher(store, f, 3, 10, 60_000);
        d.dispatchOnce();
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定依据=resumePosition=2 处理顺序=" + order
                + " 最终状态=2,3 均 SENT，1 未被重复处理");
        assertEquals(List.of(2L, 3L), order);
        assertEquals(-1L, store.resumePosition());
    }

    @Test
    void stuckInflightIsReclaimedAfterRestart(TestInfo info) throws Exception {
        // 模拟崩溃：旧进程把条目置为 INFLIGHT 后死亡；新进程（新 store 实例=重启）超时后重新认领
        OutboxStore oldStore = new OutboxStore(dir.resolve("outbox.log"));
        oldStore.register(1, "k1", "p1");
        // 模拟崩溃遗留：认领为 INFLIGHT 后把认领时间拨到很久以前（旧进程已死）
        OutboxStore restarted = new OutboxStore(dir.resolve("outbox.log"));
        restarted.claimDue(10, 60_000);
        assertEquals(OutboxEntry.INFLIGHT, restarted.find(1L).orElseThrow().status());
        restarted.markInflightSince(1L, System.currentTimeMillis() - 120_000);

        OutboxStore afterRestart = new OutboxStore(dir.resolve("outbox.log"));
        ScriptedForwarder f = new ScriptedForwarder(ForwardResult.success());
        RetryDispatcher dNew = new RetryDispatcher(afterRestart, f, 3, 10, 10_000, 60_000, 1_000);
        Thread.sleep(50);
        int n = dNew.dispatchOnce(); // INFLIGHT 超过 1s 被回收重投
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 输入=崩溃遗留INFLIGHT"
                + " 判定依据=重启后超时回收 处理数=" + n
                + " 最终状态=" + afterRestart.find(1L).orElseThrow().status());
        assertEquals(1, n);
        assertEquals(OutboxEntry.SENT, afterRestart.find(1L).orElseThrow().status());
        assertEquals(1, f.calls);
    }

    @Test
    void duplicateRegistrationDoesNotCreateDuplicateForward(TestInfo info) {
        OutboxStore store = new OutboxStore(dir.resolve("outbox.log"));
        var e1 = store.register(7, "k7", "p7");
        var e2 = store.register(7, "k7", "p7");
        assertEquals(e1.id(), e2.id());
        assertEquals(1, store.all().size());
        ScriptedForwarder f = new ScriptedForwarder(ForwardResult.success());
        dispatcher(store, f, 3, 10, 60_000).dispatchOnce();
        assertEquals(1, f.calls);
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定=同账本序号重复register返回同一条目"
                + " 最终状态=只转发一次");
    }

    @Test
    void errorOutcomesAreCategorized(TestInfo info) {
        ScriptedForwarder f = new ScriptedForwarder();
        assertEquals(ForwardOutcome.SUCCESS, ForwardResult.success().outcome());
        assertEquals(ForwardOutcome.RETRYABLE,
                ForwardResult.retryable("HTTP_503", "").outcome());
        assertEquals(ForwardOutcome.NON_RETRYABLE,
                ForwardResult.nonRetryable("HTTP_400", "").outcome());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定依据=三种类别枚举可区分 最终状态=分类正确");
    }

    @Test
    void tornOutboxTailIsTruncatedAndReplayable(TestInfo info) throws Exception {
        Path f = dir.resolve("outbox.log");
        OutboxStore store = new OutboxStore(f);
        store.register(1, "k1", "p1");
        store.markSent(1L);
        // 模拟崩溃：尾部追加未写完的半行（无换行结尾、非合法 JSON）
        java.nio.file.Files.write(f, "HALF_WRITTEN_LINE".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                java.nio.file.StandardOpenOption.APPEND);
        OutboxStore reopened = new OutboxStore(f);
        assertEquals(OutboxEntry.SENT, reopened.find(1L).orElseThrow().status());
        // 半行被丢弃，新登记正常继续
        reopened.register(2, "k2", "p2");
        assertEquals(2, reopened.all().size());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定=尾部半行截断后状态可重放"
                + " 最终状态=1 SENT + 2 PENDING，无半条可见");
    }
}
