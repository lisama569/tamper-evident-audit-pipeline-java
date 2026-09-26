package com.github.lisama569.tamperevidentauditpipelinejava.retention;

import java.util.List;

/**
 * 一次清除的可解释结果：清除清单、被保留清单及各自原因。
 */
public record PurgeResult(String policy, long evaluatedAtMs, List<Long> purgedSequences,
                          List<Long> retainedByLegalHold, List<Long> retainedNotExpired) {

    public int purgedCount() { return purgedSequences.size(); }
    public int heldCount() { return retainedByLegalHold.size(); }
}
