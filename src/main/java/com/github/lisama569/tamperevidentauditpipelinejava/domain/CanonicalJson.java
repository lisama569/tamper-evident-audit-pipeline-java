package com.github.lisama569.tamperevidentauditpipelinejava.domain;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 无共享依赖的规范 JSON 序列化：对象键按 Unicode 字典序排序，
 * 保证同一逻辑内容在任何时刻、任何 JVM 上产生完全一致的字节序列
 * （哈希链因此与 JVM 的 Map 迭代顺序无关）。
 *
 * <p>支持类型：Map / List / String / Boolean / Number / null / Instant（按 epoch 秒+纳秒）。
 */
public final class CanonicalJson {

    private CanonicalJson() {
    }

    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeTo(sb, value);
        return sb.toString();
    }

    private static void writeTo(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String s) {
            writeString(sb, s);
        } else if (value instanceof Boolean b) {
            sb.append(b.booleanValue());
        } else if (value instanceof Instant i) {
            // 确定且与默认 ISO 表示不同源的时间编码：epoch 秒 + 纳秒
            sb.append('"').append(i.getEpochSecond()).append('.')
              .append(String.format("%09d", i.getNano())).append('"');
        } else if (value instanceof Map<?, ?> map) {
            TreeMap<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> e : map.entrySet()) {
                sorted.put(String.valueOf(e.getKey()), e.getValue());
            }
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : sorted.entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeString(sb, e.getKey());
                sb.append(':');
                writeTo(sb, e.getValue());
            }
            sb.append('}');
        } else if (value instanceof List<?> list) {
            sb.append('[');
            boolean first = true;
            for (Object item : list) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeTo(sb, item);
            }
            sb.append(']');
        } else if (value instanceof Number n) {
            sb.append(n.toString());
        } else {
            // 其余类型退化为字符串，保证“未知字段”也不会被抹除
            writeString(sb, String.valueOf(value));
        }
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }
}
