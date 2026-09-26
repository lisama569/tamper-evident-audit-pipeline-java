package com.github.lisama569.tamperevidentauditpipelinejava.domain;

/**
 * 留存日志完整性被破坏时抛出；触发后存储进入密封（sealed）状态，
 * 新追加必须被明确拒绝，直至人工介入。
 */
public class StorageStateException extends RuntimeException {

    /** 最早受影响记录序号；-1 表示锚点/帧级破坏无法定位到具体记录。 */
    private final long firstAffectedSeq;

    public StorageStateException(long firstAffectedSeq, String message) {
        super(message);
        this.firstAffectedSeq = firstAffectedSeq;
    }

    public StorageStateException(long firstAffectedSeq, String message, Throwable cause) {
        super(message, cause);
        this.firstAffectedSeq = firstAffectedSeq;
    }

    public long getFirstAffectedSeq() { return firstAffectedSeq; }
}
