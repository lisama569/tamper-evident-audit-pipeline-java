package com.github.lisama569.tamperevidentauditpipelinejava.ledger;

import java.util.List;

/**
 * 老数据目录的兼容/升级结论：以新版本打开旧版本写出的目录时给出明确范围，
 * 既不悄悄降级，也不直接报错。
 */
public record CompatibilityReport(boolean legacy, String ledgerVersion,
                                  List<String> capabilities, List<String> limitations) {
}
