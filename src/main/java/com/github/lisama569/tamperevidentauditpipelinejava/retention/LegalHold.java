package com.github.lisama569.tamperevidentauditpipelinejava.retention;

/**
 * 法律保留（legal hold）：命中记录在任何情况下都不得被清除。
 */
public record LegalHold(String holdId, String subjectPattern, String reason, long createdAtMs) {
}
