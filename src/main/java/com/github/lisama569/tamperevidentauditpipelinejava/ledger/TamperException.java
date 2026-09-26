package com.github.lisama569.tamperevidentauditpipelinejava.ledger;

/**
 * 检测到账本被篡改/删除/重排时抛出；firstTamperedSequence 指向最早受影响记录。
 * 若在打开阶段抛出，{@link #ledger()} 可返回一个已 closed 的降级只读实例（可能为 null）。
 */
public class TamperException extends RuntimeException {

    private final long firstTamperedSequence;
    private transient AppendOnlyLedger ledger;

    public TamperException(long firstTamperedSequence, String message) {
        super(message);
        this.firstTamperedSequence = firstTamperedSequence;
    }

    public TamperException withLedger(AppendOnlyLedger l) {
        this.ledger = l;
        return this;
    }

    public long getFirstTamperedSequence() {
        return firstTamperedSequence;
    }

    public AppendOnlyLedger ledger() {
        return ledger;
    }
}
