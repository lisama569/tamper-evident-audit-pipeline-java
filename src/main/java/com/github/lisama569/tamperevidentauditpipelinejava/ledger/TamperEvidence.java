package com.github.lisama569.tamperevidentauditpipelinejava.ledger;

/**
 * 破坏证据分类：核验结论除最早受影响序号外，还说明“以什么依据判定为哪类破坏”。
 */
public enum TamperEvidence {
    OK,
    CONTENT_ALTERED,       // 某帧内容被改（HMAC/CRC 不匹配，或 DEK 被私删）
    MIDDLE_FRAME_MISSING,  // 中间缺帧（序号/位置向前跳跃）
    TAIL_RECORDS_MISSING,  // 相对已提交锚点，末尾整条记录缺失
    REORDERED,             // 相邻帧顺序被调换
    HALF_FRAME_TAIL,       // 末尾出现无合法写入意图的半条记录
    UNEXPECTED_TAIL_FRAME, // 已提交之后出现来源不明的完整帧
    CHAIN_TAMPERED         // 其它链结构破坏（prev 指针不符等）
}
