package com.github.lisama569.tamperevidentauditpipelinejava.ingest;

/**
 * 单条提交的结论类别。
 */
public enum IngestOutcome {
    /** 新记录已留存。 */
    ACCEPTED,
    /** 命中稳定幂等键，返回首次留存的记录，不重复写入。 */
    DUPLICATE,
    /** 校验未通过（原因见 reason/field/message），绝不静默丢弃。 */
    REJECTED,
    /** 留存存储完整性被破坏，追加被明确拒绝。 */
    STORAGE_SEALED
}
