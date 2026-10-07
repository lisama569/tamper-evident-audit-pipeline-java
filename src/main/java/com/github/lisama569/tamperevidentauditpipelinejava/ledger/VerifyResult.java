package com.github.lisama569.tamperevidentauditpipelinejava.ledger;

/**
 * 一次核验的结论：是否健康、最早受影响数据序号、破坏类型、覆盖的帧/序号范围与判定依据。
 * 结论由磁盘内容与锚点纯函数式重算，不依赖任何运行期内存状态。
 */
public record VerifyResult(boolean healthy, long firstTamperedSequence, TamperEvidence evidence,
                           String detail, long fromSequence, long toSequence,
                           int framesExamined, boolean fromCheckpoint) {

    public static VerifyResult ok(long fromSeq, long toSeq, int framesExamined, boolean fromCheckpoint) {
        return new VerifyResult(true, -1L, TamperEvidence.OK, "OK",
                fromSeq, toSeq, framesExamined, fromCheckpoint);
    }
}
