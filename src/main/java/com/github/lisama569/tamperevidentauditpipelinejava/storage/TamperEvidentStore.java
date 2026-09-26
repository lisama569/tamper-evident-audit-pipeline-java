package com.github.lisama569.tamperevidentauditpipelinejava.storage;

import com.github.lisama569.tamperevidentauditpipelinejava.domain.AuditEvent;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StorageStateException;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 防篡改只追加留存存储。
 *
 * <p>并发契约：
 * <ul>
 *   <li>{@link #append} 在锁内完成“哈希链推进 + 帧落盘 + 锚点原子更新”，
 *       因此分配的 {@code seq} 全局唯一且无空洞；</li>
 *   <li>写入路径先 fsync 段文件、再原子替换锚点，崩溃后重启会截断未被锚点
 *       覆盖的尾部半帧，已确认（锚点之前）的记录绝不会出现半条可见；</li>
 *   <li>启动校验一旦发现哈希链断裂、帧签名错误或与锚点不符，立即进入密封
 *       （sealed）状态，此后一切追加抛出 {@link StorageStateException}，
 *       错误中给出最早受影响的序号。</li>
 * </ul>
 */
public interface TamperEvidentStore {

    /** 追加一条事件，返回带序号与哈希的已留存记录。存储被密封时抛出 StorageStateException。 */
    StoredRecord append(AuditEvent event);

    /** 按序号读取（序号从 1 开始，无空洞；清除后部分序号可能不存在）。 */
    Optional<StoredRecord> get(long seq);

    /** 读取当前全部可见记录（按序号升序）。 */
    List<StoredRecord> all();

    /** 已被合规清除（墓碑/物理压实）的序号集合。 */
    Set<Long> erasedSeqs();

    /**
     * 物理清除（压实）：从段文件中彻底移除给定序号记录，幸存者重写为新段并重算哈希链，
     * 原子切换后更新锚点。返回压实后的全部可见记录。不在集合内的记录字节级保留其内容，
     * 但其哈希链链接会因重锚而改变（由调用方写入 compaction 凭证备案）。
     */
    List<StoredRecord> eraseAndCompact(Set<Long> seqsToRemove);

    /** 逻辑墓碑：仅标记清除，记录字节仍保留在链上（默认模式，安全可逆证据更强）。 */
    void markTombstones(Set<Long> seqsToTombstone);

    /** 末尾序号（已确认锚点的最大值；空存储为 0）。 */
    long lastSeq();

    /** 存储是否因检测到破坏而被密封。 */
    boolean isSealed();

    /** 若被密封，返回最早受影响序号（-1 表示锚点/帧级破坏）。 */
    long firstAffectedSeq();

    /** 密封原因（人类可读，含定位依据）。 */
    String sealedReason();
}
