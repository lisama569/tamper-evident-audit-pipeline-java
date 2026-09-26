package com.github.lisama569.tamperevidentauditpipelinejava.ingest;

import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;
import com.github.lisama569.tamperevidentauditpipelinejava.storage.TamperEvidentStore;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 稳定幂等键去重索引。
 *
 * <p>启动时从已留存日志全量重建（只追加日志是唯一事实来源）；
 * 运行期用 {@link ConcurrentHashMap#putIfAbsent} 抢占：
 * 抢占成功者才进入追加，保证同一幂等键的并发重复提交不会产生两条记录。
 * 追加若失败必须释放占位（{@link #release}），否则失败请求会把键“焊死”。
 */
@Component
public class IdempotencyIndex {

    /** 尝试占用一个键的结果。 */
    public sealed interface AcquireResult {
        /** 占位成功，调用方可以执行追加。 */
        record Acquired() implements AcquireResult {}
        /** 该键已有已留存记录，返回序号。 */
        record Existing(long seq) implements AcquireResult {}
        /** 同键的另一次提交正在追加（极短窗口）。 */
        record InFlight() implements AcquireResult {}
    }

    private static final Long PENDING = Long.MIN_VALUE;

    private final ConcurrentHashMap<String, Long> keyToSeq = new ConcurrentHashMap<>();

    public IdempotencyIndex(TamperEvidentStore store) {
        for (StoredRecord r : store.all()) {
            keyToSeq.put(r.event().idempotencyKey(), r.seq());
        }
    }

    public AcquireResult tryAcquire(String idempotencyKey) {
        Long existing = keyToSeq.get(idempotencyKey);
        if (existing != null && existing != PENDING) {
            return new AcquireResult.Existing(existing);
        }
        Long prev = keyToSeq.putIfAbsent(idempotencyKey, PENDING);
        if (prev == null) {
            return new AcquireResult.Acquired();
        }
        if (prev == PENDING) {
            return new AcquireResult.InFlight();
        }
        return new AcquireResult.Existing(prev);
    }

    /** 追加成功后把占位绑定到真实序号。 */
    public void bind(String idempotencyKey, long seq) {
        keyToSeq.put(idempotencyKey, seq);
    }

    /** 追加失败时释放占位，允许客户端修正后用同一键重试。 */
    public void release(String idempotencyKey) {
        keyToSeq.remove(idempotencyKey);
    }

    public Optional<Long> seqOf(String idempotencyKey) {
        return Optional.ofNullable(keyToSeq.get(idempotencyKey)).filter(seq -> seq != PENDING);
    }

    /** 该键是否正处于“占用中、尚未绑定序号”的窗口。 */
    public boolean isPending(String idempotencyKey) {
        return PENDING.equals(keyToSeq.get(idempotencyKey));
    }
}
