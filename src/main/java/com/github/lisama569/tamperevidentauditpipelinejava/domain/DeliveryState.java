package com.github.lisama569.tamperevidentauditpipelinejava.domain;

/**
 * 转发状态机。
 *
 * <ul>
 *   <li>{@code PENDING}：已留存但尚未成功转发；</li>
 *   <li>{@code IN_FLIGHT}：已领取投递权（带过期恢复机制），重启后可预期地续投；</li>
 *   <li>{@code DELIVERED}：对端明确 ACK，终态；</li>
 *   <li>{@code DEAD_LETTER}：不可重试错误或重试耗尽，等待人工/显式重放。</li>
 * </ul>
 */
public enum DeliveryState {
    PENDING,
    IN_FLIGHT,
    DELIVERED,
    DEAD_LETTER
}
