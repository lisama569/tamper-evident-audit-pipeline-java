package com.github.lisama569.tamperevidentauditpipelinejava.domain;

import java.util.List;

/**
 * 一次合规清除/保留到期清除的结果，保证可解释。
 *
 * @param mode            ERASURE（物理清除）或 LOGICAL_TOMBSTONE（逻辑墓碑）
 * @param eligible        通过保留策略判定、可清除的序号
 * @param blockedByHold   处于法律保留而被阻止清除的序号
 * @param purged          实际被清除的序号（逻辑模式下与 eligible 相同）
 */
public record PurgeReport(
        String mode,
        List<Long> eligible,
        List<Long> blockedByHold,
        List<Long> purged
) {
}
