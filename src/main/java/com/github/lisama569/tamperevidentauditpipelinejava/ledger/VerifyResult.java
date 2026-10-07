package com.github.lisama569.tamperevidentauditpipelinejava.ledger;

/**
 * 一次（可能分段的）完整性核验结论。
 *
 * <p>范围以 DATA 序号表达；物理上核验会从范围内最近的 CHECKPOINT 锚点开始，
 * 因此分段拼接与一次性全量核验结论一致。firstTamperedSequence=-1 表示范围内未发现破坏。
 */
public record VerifyResult(long fromSeqInclusive, long toSeqInclusive, long firstTamperedSequence,
                           int framesChecked, long anchoredAfterDataSeq, boolean healthy,
                           String basis) {

    public static VerifyResult healthy(long from, long to, int framesChecked,
                                       long anchoredAfterDataSeq, String basis) {
        return new VerifyResult(from, to, -1L, framesChecked, anchoredAfterDataSeq, true, basis);
    }

    public static VerifyResult tampered(long from, long to, long firstTampered, int framesChecked,
                                        long anchoredAfterDataSeq, String basis) {
        return new VerifyResult(from, to, firstTampered, framesChecked, anchoredAfterDataSeq, false, basis);
    }
}
