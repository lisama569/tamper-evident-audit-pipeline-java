package com.github.lisama569.tamperevidentauditpipelinejava.storage;

/**
 * 防“全删/截断到空”的可信锚点（持久化在独立的 anchor 文件中，原子更新）。
 *
 * <p>每追加一条记录后同步更新锚点；启动时日志必须与锚点一致：
 * 即使整个段文件被删除或截断，锚点仍能指出“应当存在多少条、末端哈希为何”。
 */
public record Anchor(
        long lastSeq,
        String lastHash,
        long length,
        String signature
) {
    /** 空存储的初始锚点。 */
    public static Anchor empty() {
        return new Anchor(0, "0".repeat(64), 0L, "");
    }
}
